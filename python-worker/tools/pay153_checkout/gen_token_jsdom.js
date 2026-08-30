/**
 * 用 jsdom 提供完整 window, eval SDK, 提取内部函数
 */
const { JSDOM } = require("jsdom");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

let input = {};
try {
  input = JSON.parse(fs.readFileSync(process.argv[2], "utf-8"));
} catch (error) {
  console.error("Input JSON error:", error.message);
  process.exit(1);
}

// 读取与部署包放在一起的 Sentinel SDK，避免依赖开发机私有目录。
const sdkPath = process.env.SENTINEL_SDK_PATH || path.join(__dirname, "sentinel_sdk_full.js");
let sdkCode = fs.readFileSync(sdkPath, "utf-8");
sdkCode = sdkCode.replace(/^"var SentinelSDK/, "var SentinelSDK");
sdkCode = sdkCode.replace(/\\n"$/, "");
sdkCode = sdkCode.replace(/\\"/g, '"');
sdkCode = sdkCode.replace(/\\n/g, "\n");
sdkCode = sdkCode.replace(/\\\\/g, "\\");

// Hook: 在 SDK IIFE 末尾 (t.token=ye 后) 暴露内部函数
// SDK 结尾: t.sessionObserverToken=async function...; t.token=ye; t}({});
// 我们在 t}({}) 前插入暴露代码
let hookedCode = sdkCode
  .replace("t.token=ye,t}({});", "t.___n=_n,t.__Nt=Nt,t.__D=D,t.__$=$,t.token=ye,t}({});")
  .replace("var P=new _;", "var P=new _;globalThis.__debugP=P;")

// 验证替换
if (hookedCode === sdkCode) {
  console.error("WARNING: Hook replacement did not match!");
  // 尝试找模式
  const idx = sdkCode.indexOf("t.token=ye");
  console.error("t.token=ye at pos:", idx);
  if (idx >= 0) console.error("Context:", sdkCode.substring(idx, idx + 30));
} else {
  console.log("Hook replacement OK");
}

// 创建 jsdom
const dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
  url: "https://auth.openai.com/about-you",
  referrer: "https://auth.openai.com/about-you",
  contentType: "text/html",
  runScripts: "outside-only",
  pretendToBeVisual: true,
});

const { window } = dom;

// Keep the SDK fingerprint aligned with the HTTP authentication session.  The
// jsdom default user agent ("jsdom/...") is readily detectable and can cause
// Sentinel authorize_continue to reject an otherwise valid proof.
const userAgent = String(input.userAgent || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36");
Object.defineProperty(window.navigator, "userAgent", { value: userAgent, configurable: true });
Object.defineProperty(window.navigator, "language", { value: "ja-JP", configurable: true });
Object.defineProperty(window.navigator, "languages", { value: ["ja-JP", "ja", "en"], configurable: true });
Object.defineProperty(window.navigator, "platform", { value: "Win32", configurable: true });
Object.defineProperty(window.navigator, "hardwareConcurrency", { value: 8, configurable: true });
Object.defineProperty(window.navigator, "webdriver", { value: false, configurable: true });
for (const [name, value] of Object.entries({ width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24 })) {
  try { Object.defineProperty(window.screen, name, { value, configurable: true }); } catch (_) {}
}

// 补充 crypto
if (!window.crypto) window.crypto = {};
window.crypto.getRandomValues = (arr) => {
  const buf = crypto.randomBytes(arr.length);
  for (let i = 0; i < arr.length; i++) arr[i] = buf[i];
  return arr;
};
if (!window.crypto.randomUUID) window.crypto.randomUUID = () => crypto.randomUUID();

// 补充 performance.memory
if (!window.performance.memory) {
  window.performance.memory = {
    jsHeapSizeLimit: 4294705152,
    totalJSHeapSize: 35000000,
    usedJSHeapSize: 25000000,
  };
}

// 在 window 上下文中 eval SDK
const vm = require("vm");
const context = dom.getInternalVMContext();

try {
  vm.runInContext(hookedCode, context, { filename: "sentinel_sdk.js" });
} catch (e) {
  console.error("SDK run error:", e.message);
  console.error(e.stack?.substring(0, 500));
}

// Protocol registration uses the real SDK for both sides of the challenge:
// requirements token before /req, and enforcement token after /req. Keep this
// path separate from the legacy diagnostic mode below so Pay153 callers keep
// their existing output contract.
if (input.action === "requirements" || input.action === "solve") {
  (async () => {
    try {
      if (!window.SentinelSDK || !window.__debugP) throw new Error("Sentinel SDK runtime unavailable");
      if (input.action === "requirements") {
        const requestP = await window.__debugP.getRequirementsToken();
        console.log("=== JSON_OUTPUT ===");
        console.log(JSON.stringify({ request_p: requestP }));
        return;
      }
      const chatReq = input.chatReq || {};
      const requestP = String(input.cachedProof || "").trim();
      if (!requestP) throw new Error("missing cachedProof");
      const finalP = await window.__debugP.getEnforcementToken(chatReq);
      if (typeof window.SentinelSDK.__D !== "function" || typeof window.SentinelSDK.___n !== "function") {
        throw new Error("Sentinel SDK browser proof functions unavailable");
      }
      window.SentinelSDK.__D(chatReq, requestP);
      const dx = chatReq.turnstile && chatReq.turnstile.dx;
      const t = dx ? await window.SentinelSDK.___n(chatReq, dx) : null;
      let so = null;
      const observer = chatReq.so || {};
      if (observer.collector_dx && typeof window.SentinelSDK.__Nt === "function") {
        so = await window.SentinelSDK.__Nt(observer.collector_dx);
      }
      console.log("=== JSON_OUTPUT ===");
      console.log(JSON.stringify({ final_p: finalP, t, so }));
    } catch (error) {
      console.error(error && error.stack ? error.stack : String(error));
      process.exitCode = 1;
    }
  })();
} else {

console.log("SentinelSDK:", typeof window.SentinelSDK);
console.log("___n:", typeof window.SentinelSDK?.___n);
console.log("__Nt:", typeof window.SentinelSDK?.__Nt);
console.log("__D:", typeof window.SentinelSDK?.__D);
console.log("__$:", typeof window.SentinelSDK?.__$);

// 如果成功提取了 _n, 测试执行
if (typeof window.SentinelSDK?.___n === "function") {
  const _n = window.SentinelSDK.___n;
  const Nt = window.SentinelSDK.__Nt;
  const D = window.SentinelSDK.__D;
  const input = JSON.parse(fs.readFileSync(process.argv[2], "utf-8"));
  const { chatReq, flow, deviceId, cachedProof } = input;

  const turnstileDx = chatReq.turnstile?.dx || null;
  console.log("\n--- Testing turnstile VM ---");
  console.log("dx length:", turnstileDx ? turnstileDx.length : 0);
  console.log("proof:", cachedProof.substring(0, 50) + "...");

  // 设置 WeakMap: D(chatReq, cachedProof)
  if (typeof D === "function") {
    D(chatReq, cachedProof);
    console.log("WeakMap set OK");
  }

  // 调用 _n(chatReq, dx)；没有 turnstile challenge 时保留空 t。
  const turnstilePromise = turnstileDx ? _n(chatReq, turnstileDx) : Promise.resolve(null);
  turnstilePromise.then(result => {
    console.log("\nTurnstile result:");
    console.log("  type:", typeof result);
    console.log("  length:", result == null ? 0 : String(result).length);
    console.log("  preview:", String(result).substring(0, 100));

    // 测试 SO VM
    if (typeof Nt === "function" && chatReq.so?.collector_dx) {
      console.log("\n--- Testing SO VM ---");
      Nt(chatReq.so.collector_dx).then(soResult => {
        console.log("SO result:");
        console.log("  type:", typeof soResult);
        console.log("  length:", String(soResult).length);
        console.log("  preview:", String(soResult).substring(0, 100));

        // 输出 JSON
        const output = { t: result, so: soResult, flow, deviceId };
        console.log("\n=== JSON_OUTPUT ===");
        console.log(JSON.stringify(output));
        process.exit(0);
      }).catch(e => {
        console.error("SO VM error:", e.message);
        const output = { t: result, so: null, flow, deviceId };
        console.log("\n=== JSON_OUTPUT ===");
        console.log(JSON.stringify(output));
        process.exit(0);
      });
    } else {
      const output = { t: result, so: null, flow, deviceId };
      console.log("\n=== JSON_OUTPUT ===");
      console.log(JSON.stringify(output));
      process.exit(0);
    }
  }).catch(e => {
    console.error("Turnstile VM error:", e.message);
    process.exit(1);
  });
} else {
  console.error("Failed to extract _n");
  process.exit(1);
}

setTimeout(() => {
  console.error("Timeout: 30s");
  process.exit(1);
}, 30000);
}
