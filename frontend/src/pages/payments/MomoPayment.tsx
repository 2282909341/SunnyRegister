import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import {
  Activity, CheckCircle2, Clipboard, ExternalLink, FileUp, Gauge, Link2,
  Loader2, Play, RefreshCw, ShieldCheck, Square, Trash2, Upload, UsersRound,
  WalletCards, XCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { API_BASE, apiFetch, cn } from "@/lib/utils";

type Row = Record<string, any>;

type MomoPreferences = {
  checkoutProxies?: string;
  promotionProxies?: string;
  externalText?: string;
  selected?: number[];
  plan?: string;
  retryCount?: number;
  concurrency?: number;
  usePromo?: boolean;
  promoCampaign?: string;
  workspaceName?: string;
  workspaceId?: string;
  seatQuantity?: number;
  priceInterval?: string;
  creditQuantity?: number;
};

type MomoAT = {
  index: number;
  raw: string;
  token: string;
  email: string;
  status: "ready" | "expired" | "invalid";
  expiresAt: string;
};

type MomoTaskAccount = {
  taskIndex: number;
  sourceIndex: number;
  email: string;
};

type MomoAccountState = {
  index: number;
  email: string;
  progress: number;
  message: string;
  status: "pending" | "running" | "succeeded" | "failed" | "cancelled";
  result?: Row;
};

const preferencesStorageKey = "sunnyregister.payments.momo.preferences.v1";
const taskStorageKey = "sunnyregister.payments.momo.last-task-id.v1";
const taskAccountsStorageKey = "sunnyregister.payments.momo.task-accounts.v1";
const emailPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;

function readStorageText(key: string) {
  if (typeof window === "undefined") return "";
  try { return window.localStorage.getItem(key) || ""; } catch { return ""; }
}

function readPreferences(): MomoPreferences {
  try {
    const parsed = JSON.parse(readStorageText(preferencesStorageKey) || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch { return {}; }
}

function readTaskAccounts(): MomoTaskAccount[] {
  try {
    const parsed = JSON.parse(readStorageText(taskAccountsStorageKey) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.flatMap((item) => {
      const taskIndex = Number(item?.taskIndex);
      if (!Number.isInteger(taskIndex) || taskIndex < 0) return [];
      return [{ taskIndex, sourceIndex: Number(item?.sourceIndex ?? -1), email: String(item?.email || "") }];
    });
  } catch { return []; }
}

function clampNumber(value: unknown, fallback: number, minimum: number, maximum: number) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(maximum, Math.max(minimum, Math.trunc(parsed))) : fallback;
}

function decodeAT(token: string, now: number) {
  const parts = token.split(".");
  if (parts.length < 2) return { email: "", expiresAt: "", expired: false };
  try {
    const encoded = parts[1].replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(parts[1].length / 4) * 4, "=");
    const raw = decodeURIComponent(Array.from(atob(encoded), (char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""));
    const payload = JSON.parse(raw);
    const profile = payload["https://api.openai.com/profile"] || {};
    const expires = Number(payload.exp || 0);
    return {
      email: String(payload.email || profile.email || ""),
      expiresAt: expires > 0 ? new Date(expires * 1000).toISOString() : "",
      expired: expires > 0 && expires * 1000 <= now,
    };
  } catch { return { email: "", expiresAt: "", expired: false }; }
}

function parseATLine(raw: string, index: number, now: number): MomoAT {
  const value = raw.trim();
  let token = value.split(/\s+/)[0] || "";
  let email = value.match(emailPattern)?.[0] || "";
  let storedRaw = value;
  if (value.startsWith("{")) {
    try {
      const parsed = JSON.parse(value);
      token = String(parsed.access_token || parsed.accessToken || parsed.token || "").trim();
      email = String(parsed.email || email).trim();
      storedRaw = JSON.stringify({ access_token: token, ...(email ? { email } : {}) });
    } catch { token = ""; }
  }
  const decoded = decodeAT(token, now);
  const structurallyValid = token.startsWith("eyJ") && token.includes(".");
  return {
    index,
    raw: storedRaw,
    token,
    email: email || decoded.email || `外部账户 ${index + 1}`,
    status: !structurallyValid ? "invalid" : decoded.expired ? "expired" : "ready",
    expiresAt: decoded.expiresAt,
  };
}

function collectATEntries(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(collectATEntries);
  if (typeof value === "string") {
    const token = value.trim().split(/\s+/)[0] || "";
    return token.startsWith("eyJ") && token.includes(".") ? [value] : [];
  }
  if (!value || typeof value !== "object") return [];
  const row = value as Row;
  if (row.access_token || row.accessToken || row.token) return [JSON.stringify(row)];
  return Object.values(row).flatMap(collectATEntries);
}

function parseATText(value: string, now: number) {
  const trimmed = value.trim();
  if (!trimmed) return [];
  try {
    const entries = collectATEntries(JSON.parse(trimmed));
    if (entries.length) return entries.map((entry, index) => parseATLine(entry, index, now));
  } catch { /* Fall back to line-oriented text or JSONL. */ }
  return trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line, index) => parseATLine(line, index, now));
}

function normalized(value: unknown) { return String(value || "").trim().toLowerCase(); }

function taskStatusLabel(value: unknown) {
  return ({
    pending: "等待中", claimed: "已领取", running: "运行中", succeeded: "已完成",
    failed: "失败", cancelled: "已停止", cancel_requested: "停止中",
  } as Record<string, string>)[normalized(value)] || String(value || "未开始");
}

function accountStatusLabel(value: MomoAccountState["status"]) {
  return ({ pending: "待执行", running: "进行中", succeeded: "成功", failed: "失败", cancelled: "已停止" } as const)[value];
}

function resultLink(result?: Row) {
  if (!result) return "";
  return String(result.payment_link || result.provider_redirect_url || result.short_link || result.checkout_url || result.verification_url || "").trim();
}

function resultError(result?: Row) {
  return String(result?.error || result?.checkout_error || result?.message || "").trim();
}

function resultExpired(result: Row | undefined, now = Date.now()) {
  const raw = result?.expires_at;
  if (raw == null || raw === "") return false;
  const numeric = Number(raw);
  const expiresAt = Number.isFinite(numeric) && numeric > 0
    ? numeric * (numeric < 1_000_000_000_000 ? 1000 : 1)
    : new Date(String(raw)).getTime();
  return Number.isFinite(expiresAt) && expiresAt <= now;
}

function mergeResultStates(previous: Record<string, MomoAccountState>, items: Row[]) {
  const next = { ...previous };
  items.forEach((item, fallbackIndex) => {
    const parsedIndex = Number(item?.index);
    const index = Number.isInteger(parsedIndex) && parsedIndex >= 0 ? parsedIndex : fallbackIndex;
    const key = String(index);
    const current = next[key] || { index, email: "", progress: 0, message: "等待执行", status: "pending" as const };
    const succeeded = normalized(item?.status) === "succeeded" && Boolean(resultLink(item));
    next[key] = {
      ...current,
      email: String(item?.email || current.email || `账户 ${index + 1}`),
      progress: 100,
      message: succeeded ? "MOMO 授权链接已生成" : resultError(item) || "MOMO 提链失败",
      status: succeeded ? "succeeded" : "failed",
      result: item,
    };
  });
  return next;
}

function formatTime(value: unknown) {
  if (!value) return "-";
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("zh-CN", { hour12: false });
}

function formatAmount(result?: Row) {
  if (!result || result.checkout_amount == null || result.checkout_amount === "") return "-";
  const amount = Number(result.checkout_amount);
  const rendered = Number.isFinite(amount) ? amount.toLocaleString("vi-VN") : String(result.checkout_amount);
  return `${rendered} ${String(result.amount_currency || result.currency || "VND")}`;
}

export default function MomoPayment() {
  const savedPreferences = useMemo(() => readPreferences(), []);
  const savedTaskID = useMemo(() => readStorageText(taskStorageKey), []);
  const [clock, setClock] = useState(() => Date.now());
  const initialAccounts = useMemo(() => parseATText(String(savedPreferences.externalText || ""), clock), [clock, savedPreferences.externalText]);
  const initialSelected = useMemo(() => {
    const valid = new Set(initialAccounts.filter((item) => item.status === "ready").map((item) => item.index));
    if (Array.isArray(savedPreferences.selected)) return savedPreferences.selected.map(Number).filter((item) => valid.has(item));
    return Array.from(valid);
  }, [initialAccounts, savedPreferences.selected]);
  const [checkoutProxies, setCheckoutProxies] = useState(String(savedPreferences.checkoutProxies || ""));
  const [promotionProxies, setPromotionProxies] = useState(String(savedPreferences.promotionProxies || ""));
  const [externalText, setExternalText] = useState(String(savedPreferences.externalText || ""));
  const [importText, setImportText] = useState("");
  const [selected, setSelected] = useState<number[]>(initialSelected);
  const [plan, setPlan] = useState(["plus", "pro", "team", "codex_low"].includes(String(savedPreferences.plan)) ? String(savedPreferences.plan) : "plus");
  const [retryCount, setRetryCount] = useState(() => clampNumber(savedPreferences.retryCount, 10, 0, 50));
  const [concurrency, setConcurrency] = useState(() => clampNumber(savedPreferences.concurrency, 3, 1, 100));
  const [usePromo, setUsePromo] = useState(savedPreferences.usePromo ?? true);
  const [promoCampaign, setPromoCampaign] = useState(String(savedPreferences.promoCampaign || "plus-1-month-free"));
  const [workspaceName, setWorkspaceName] = useState(String(savedPreferences.workspaceName || "MOMO Workspace"));
  const [workspaceId, setWorkspaceId] = useState(String(savedPreferences.workspaceId || ""));
  const [seatQuantity, setSeatQuantity] = useState(() => clampNumber(savedPreferences.seatQuantity, 5, 2, 100));
  const [priceInterval, setPriceInterval] = useState(savedPreferences.priceInterval === "year" ? "year" : "month");
  const [creditQuantity, setCreditQuantity] = useState(() => clampNumber(savedPreferences.creditQuantity, 13, 1, 10000));
  const [checks, setChecks] = useState<Record<string, Row>>({});
  const [precheckBusy, setPrecheckBusy] = useState(false);
  const [checkoutBusy, setCheckoutBusy] = useState(Boolean(savedTaskID));
  const [cancelBusy, setCancelBusy] = useState(false);
  const [task, setTask] = useState<Row | null>(null);
  const [activeTaskID, setActiveTaskID] = useState(savedTaskID);
  const [taskAccounts, setTaskAccounts] = useState<MomoTaskAccount[]>(() => savedTaskID ? readTaskAccounts() : []);
  const [accountStates, setAccountStates] = useState<Record<string, MomoAccountState>>(() => Object.fromEntries((savedTaskID ? readTaskAccounts() : []).map((item) => [String(item.taskIndex), { index: item.taskIndex, email: item.email, progress: 0, message: "正在恢复任务状态", status: "pending" as const }])));
  const [taskLogs, setTaskLogs] = useState<Row[]>([]);
  const [notice, setNotice] = useState<{ type: "ok" | "error"; text: string } | null>(null);
  const [watchError, setWatchError] = useState("");
  const noticeTimer = useRef(0);

  const accounts = parseATText(externalText, clock);
  const selectedAccounts = accounts.filter((item) => selected.includes(item.index) && item.status === "ready");
  const proxyCount = useMemo(() => new Set(checkoutProxies.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)).size, [checkoutProxies]);
  const promotionProxyCount = useMemo(() => new Set(promotionProxies.split(/\r?\n/).map((item) => item.trim()).filter(Boolean)).size, [promotionProxies]);
  const taskRows = useMemo(() => {
    const indexes = new Set<number>([
      ...taskAccounts.map((item) => item.taskIndex),
      ...Object.values(accountStates).map((item) => item.index),
    ]);
    const context = new Map(taskAccounts.map((item) => [item.taskIndex, item]));
    return Array.from(indexes).sort((a, b) => a - b).map((index) => {
      const state = accountStates[String(index)];
      return state || { index, email: context.get(index)?.email || `账户 ${index + 1}`, progress: 0, message: "等待执行", status: "pending" as const };
    });
  }, [accountStates, taskAccounts]);
  const successCount = taskRows.filter((item) => item.status === "succeeded" && !resultExpired(item.result, clock)).length;
  const runningCount = taskRows.filter((item) => item.status === "running").length;
  const configBusy = checkoutBusy || precheckBusy;

  const notify = useCallback((text: string, type: "ok" | "error" = "ok") => {
    window.clearTimeout(noticeTimer.current);
    setNotice({ text, type });
    noticeTimer.current = window.setTimeout(() => setNotice((current) => current?.text === text ? null : current), 3200);
  }, []);

  useEffect(() => () => window.clearTimeout(noticeTimer.current), []);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => {
    try {
      const preferences: MomoPreferences = {
        checkoutProxies, promotionProxies, externalText, selected, plan, retryCount, concurrency, usePromo,
        promoCampaign, workspaceName, workspaceId, seatQuantity, priceInterval, creditQuantity,
      };
      window.localStorage.setItem(preferencesStorageKey, JSON.stringify(preferences));
    } catch { /* Browser storage can be unavailable in private mode. */ }
  }, [checkoutProxies, concurrency, creditQuantity, externalText, plan, priceInterval, promoCampaign, promotionProxies, retryCount, seatQuantity, selected, usePromo, workspaceId, workspaceName]);
  useEffect(() => {
    try {
      if (activeTaskID) window.localStorage.setItem(taskStorageKey, activeTaskID);
      else window.localStorage.removeItem(taskStorageKey);
    } catch { /* Browser storage can be unavailable in private mode. */ }
  }, [activeTaskID]);
  useEffect(() => {
    try {
      if (activeTaskID) window.localStorage.setItem(taskAccountsStorageKey, JSON.stringify(taskAccounts));
      else window.localStorage.removeItem(taskAccountsStorageKey);
    } catch { /* Browser storage can be unavailable in private mode. */ }
  }, [activeTaskID, taskAccounts]);

  useEffect(() => {
    if (!activeTaskID) return;
    let mounted = true;
    let timer = 0;
    let eventCursor = 0;
    const seenEventIDs = new Set<number>();
    let stream: EventSource | null = null;
    let streamDone = false;
    let failures = 0;

    const applyEvents = (items: Row[]) => {
      const ordered = items
        .filter((item) => {
          const id = Number(item?.id || 0);
          return id > 0 && !seenEventIDs.has(id);
        })
        .sort((left, right) => Number(left.id || 0) - Number(right.id || 0));
      if (!ordered.length) return;
      ordered.forEach((item) => seenEventIDs.add(Number(item.id || 0)));
      eventCursor = Math.max(eventCursor, ...ordered.map((item) => Number(item.id || 0)));
      setTaskLogs((current) => {
        const known = new Set(current.map((item) => Number(item.id || 0)));
        return [...current, ...ordered.filter((item) => !known.has(Number(item.id || 0)))].slice(-600);
      });
      setAccountStates((current) => {
        const next = { ...current };
        for (const event of ordered) {
          const detail = event.detail || {};
          if (event.type !== "checkout_progress" && event.type !== "checkout_result") continue;
          const parsedIndex = Number(detail.index);
          if (!Number.isInteger(parsedIndex) || parsedIndex < 0) continue;
          const key = String(parsedIndex);
          const previous = next[key] || { index: parsedIndex, email: "", progress: 0, message: "等待执行", status: "pending" as const };
          if (event.type === "checkout_result") {
            const result = detail.result && typeof detail.result === "object" ? detail.result : {};
            const succeeded = normalized(result.status) === "succeeded" && Boolean(resultLink(result));
            next[key] = {
              ...previous,
              email: String(result.email || event.email || detail.email || previous.email || `账户 ${parsedIndex + 1}`),
              progress: 100,
              message: succeeded ? "MOMO 授权链接已生成" : resultError(result) || event.message || "MOMO 提链失败",
              status: succeeded ? "succeeded" : "failed",
              result,
            };
          } else {
            if (previous.status === "succeeded" || previous.status === "failed" || previous.status === "cancelled") continue;
            next[key] = {
              ...previous,
              email: String(event.email || detail.email || previous.email || `账户 ${parsedIndex + 1}`),
              progress: Math.max(previous.progress, Number(detail.progress || 0)),
              message: String(detail.current_log || event.message || previous.message),
              status: "running",
            };
          }
        }
        return next;
      });
      setTaskAccounts((current) => {
        const next = new Map(current.map((item) => [item.taskIndex, item]));
        for (const event of ordered) {
          const detail = event.detail || {};
          const index = Number(detail.index);
          if (!Number.isInteger(index) || index < 0) continue;
          const email = String(event.email || detail.email || detail.result?.email || "");
          const previous = next.get(index);
          if (!previous) next.set(index, { taskIndex: index, sourceIndex: -1, email: email || `账户 ${index + 1}` });
          else if (!previous.email && email) next.set(index, { ...previous, email });
        }
        return Array.from(next.values()).sort((left, right) => left.taskIndex - right.taskIndex);
      });
    };

    const readEvents = async (maxPages = 5) => {
      const collected: Row[] = [];
      let cursor = eventCursor;
      for (let page = 0; page < maxPages && mounted; page += 1) {
        const data = await apiFetch(`/tasks/${encodeURIComponent(activeTaskID)}/events?since=${cursor}&limit=1000`);
        const items = Array.isArray(data.items) ? data.items : [];
        if (!items.length) break;
        cursor = Number(items[items.length - 1]?.id || cursor);
        collected.push(...items);
        if (items.length < 1000) break;
      }
      if (mounted && collected.length) applyEvents(collected);
    };

    const openStream = () => {
      if (stream || streamDone) return;
      const base = String(API_BASE || "/api").replace(/\/$/, "");
      const source = new EventSource(`${base}/tasks/${encodeURIComponent(activeTaskID)}/logs/stream?since=${eventCursor}`, { withCredentials: true });
      stream = source;
      source.onmessage = (message) => {
        try {
          const payload = JSON.parse(message.data || "{}");
          if (payload.done) {
            streamDone = true;
            source.close();
            if (stream === source) stream = null;
            return;
          }
          applyEvents([payload]);
        } catch { /* Polling remains authoritative if a frame is malformed. */ }
      };
      source.onerror = () => {
        source.close();
        if (stream === source) stream = null;
      };
    };

    const watchTask = async () => {
      while (mounted) {
        try {
          openStream();
          const current = await apiFetch(`/tasks/${encodeURIComponent(activeTaskID)}`);
          if (!mounted) return;
          if (current.type !== "sunny_checkout_link") {
            setTask(null);
            setTaskAccounts([]);
            setAccountStates({});
            setTaskLogs([]);
            setCheckoutBusy(false);
            setActiveTaskID("");
            setWatchError("");
            notify("保存的 MOMO 任务标识无效，已停止恢复", "error");
            return;
          }
          failures = 0;
          setWatchError("");
          setTask(current);
          const resultItems = Array.isArray(current?.result?.items) ? current.result.items : [];
          if (resultItems.length) setAccountStates((previous) => mergeResultStates(previous, resultItems));
          await readEvents().catch(() => undefined);
          if (current.terminal) {
            streamDone = true;
            stream?.close();
            stream = null;
            await readEvents(50).catch(() => undefined);
            const cancelled = normalized(current.status) === "cancelled";
            const terminalMessage = cancelled
              ? "任务已由用户停止"
              : String(current.error || `任务已结束：成功 ${current.success || 0}，失败 ${current.error_count || 0}`);
            setAccountStates((previous) => Object.fromEntries(Object.entries(mergeResultStates(previous, resultItems)).map(([key, value]) => [key,
              value.status === "pending" || value.status === "running"
                ? { ...value, progress: 100, message: terminalMessage, status: cancelled ? "cancelled" as const : "failed" as const }
                : value,
            ])));
            setCheckoutBusy(false);
            notify(current.status === "succeeded" ? `MOMO 任务完成：成功 ${current.success || 0}，失败 ${current.error_count || 0}` : terminalMessage, current.status === "succeeded" ? "ok" : "error");
            return;
          }
        } catch (error) {
          if (!mounted) return;
          const message = error instanceof Error ? error.message : String(error);
          if (message.toLowerCase().includes("task not found")) {
            setTask(null);
            setTaskAccounts([]);
            setAccountStates({});
            setTaskLogs([]);
            setCheckoutBusy(false);
            setActiveTaskID("");
            setWatchError("");
            notify("MOMO 任务不存在或已被清理", "error");
            return;
          }
          failures += 1;
          setWatchError(message || "任务状态读取失败");
          if (failures === 3) notify("MOMO 任务状态连续读取失败，可放弃恢复后重新提交", "error");
        }
        const delay = failures ? Math.min(15_000, 1000 * (2 ** Math.min(failures - 1, 4))) : 1000;
        await new Promise<void>((resolve) => { timer = window.setTimeout(resolve, delay); });
      }
    };

    void watchTask();
    return () => {
      mounted = false;
      window.clearTimeout(timer);
      stream?.close();
    };
  }, [activeTaskID, notify]);

  function importAccounts(value: string) {
    const incoming = parseATText(value, clock);
    if (!incoming.length) return notify("没有识别到可导入的 AT", "error");
    const existing = parseATText(externalText, clock);
    const known = new Set(existing.map((item) => item.token || item.raw));
    const additions = incoming.filter((item) => {
      const key = item.token || item.raw;
      if (known.has(key)) return false;
      known.add(key);
      return true;
    });
    if (!additions.length) return notify("导入的 AT 已存在于列表中", "error");
    const nextText = [...existing.map((item) => item.raw), ...additions.map((item) => item.raw)].join("\n");
    const nextAccounts = parseATText(nextText, clock);
    const addedStart = existing.length;
    setExternalText(nextText);
    setSelected((current) => Array.from(new Set([...current, ...nextAccounts.filter((item) => item.index >= addedStart && item.status === "ready").map((item) => item.index)])));
    setChecks({});
    setImportText("");
    notify(`已导入 ${additions.length} 个 AT`);
  }

  async function handleFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) importAccounts(await file.text());
    event.target.value = "";
  }

  function removeSelectedAccounts() {
    const doomed = new Set(selected);
    setExternalText(accounts.filter((item) => !doomed.has(item.index)).map((item) => item.raw).join("\n"));
    setSelected([]);
    setChecks({});
    notify(`已移除 ${doomed.size} 个 AT`);
  }

  function currentSelectionSnapshot() {
    const parsed = parseATText(externalText, Date.now());
    const snapshot = parsed.filter((item) => selected.includes(item.index) && item.status === "ready");
    if (snapshot.length !== selected.length) {
      setSelected(snapshot.map((item) => item.index));
      notify("部分已选 AT 已过期或失效，请确认列表后重试", "error");
      return [];
    }
    return snapshot;
  }

  async function precheck() {
    if (!usePromo || plan !== "plus") {
      return notify("当前未开启 Plus 优惠，无需进行试用资格检测");
    }
    if (!proxyCount || !promotionProxyCount) return notify("请先填写 Checkout 与 Promotion 代理池", "error");
    const snapshot = currentSelectionSnapshot();
    if (!snapshot.length) return notify("请先选择至少一个有效 AT", "error");
    setPrecheckBusy(true);
    try {
      const data = await apiFetch("/sunny/checkout/precheck", {
        method: "POST",
        body: JSON.stringify({
          system_at: false,
          session_ids: [],
          external_ats: snapshot.map((item) => item.raw),
          checkout_proxies: checkoutProxies,
          promotion_proxies: promotionProxies,
          use_promo: plan === "plus" && usePromo,
          country: "VN",
          currency: "VND",
        }),
      });
      setChecks((current) => {
        const next = { ...current };
        snapshot.forEach((account, index) => { next[String(account.index)] = data.items?.[index] || {}; });
        return next;
      });
      notify("资格与 Checkout 检测完成");
    } catch (error) { notify(error instanceof Error ? error.message : "检测失败", "error"); }
    finally { setPrecheckBusy(false); }
  }

  async function startTask() {
    if (!proxyCount) return notify("请先填写 Checkout 代理池", "error");
    if (plan === "plus" && usePromo && !promotionProxyCount) {
      return notify("开启优惠时请填写 Promotion 代理池", "error");
    }
    const snapshot = currentSelectionSnapshot();
    if (!snapshot.length) return notify("请先选择至少一个有效 AT", "error");
    if (checkoutBusy) return;
    const context = snapshot.map((account, taskIndex) => ({ taskIndex, sourceIndex: account.index, email: account.email }));
    setCheckoutBusy(true);
    setActiveTaskID("");
    setWatchError("");
    setTask(null);
    setTaskLogs([]);
    setTaskAccounts(context);
    setAccountStates(Object.fromEntries(context.map((item) => [String(item.taskIndex), { index: item.taskIndex, email: item.email, progress: 0, message: "等待任务调度", status: "pending" as const }])));
    try {
      const response = await apiFetch("/sunny/checkout", {
        method: "POST",
        body: JSON.stringify({
          system_at: false,
          session_ids: [],
          external_ats: snapshot.map((item) => item.raw),
          checkout_kinds: snapshot.map((item) => normalized(checks[String(item.index)]?.checkout_kind) || "unknown"),
          checkout_proxies: checkoutProxies,
          promotion_proxies: plan === "plus" && usePromo ? promotionProxies : "",
          plan,
          link_type: "momo",
          country: "VN",
          currency: "VND",
          retry_count: retryCount,
          concurrency,
          use_promo: plan === "plus" && usePromo,
          promo_campaign: plan === "plus" && usePromo ? promoCampaign : "",
          promo_country: "VN",
          workspace_name: workspaceName,
          workspace_id: workspaceId,
          seat_quantity: seatQuantity,
          price_interval: priceInterval,
          credit_quantity: creditQuantity,
        }),
      });
      const taskID = String(response.id || response.task_id || "");
      if (!taskID) throw new Error("服务端未返回 MOMO 任务标识");
      setTask(response);
      setActiveTaskID(taskID);
      notify("MOMO 协议支付任务已提交");
    } catch (error) {
      const message = error instanceof Error ? error.message : "MOMO 任务创建失败";
      setAccountStates((current) => Object.fromEntries(Object.entries(current).map(([key, value]) => [key, { ...value, progress: 100, message, status: "failed" as const }])));
      setCheckoutBusy(false);
      notify(message, "error");
    }
  }

  async function cancelTask() {
    if (!task?.id || task.terminal || cancelBusy) return;
    setCancelBusy(true);
    try {
      const current = await apiFetch(`/tasks/${encodeURIComponent(String(task.id))}/cancel`, { method: "POST" });
      setTask(current);
      notify("已请求停止 MOMO 任务");
    } catch (error) { notify(error instanceof Error ? error.message : "停止任务失败", "error"); }
    finally { setCancelBusy(false); }
  }

  async function refreshTask() {
    if (!activeTaskID) return;
    try {
      const current = await apiFetch(`/tasks/${encodeURIComponent(activeTaskID)}`);
      setTask(current);
      const items = Array.isArray(current?.result?.items) ? current.result.items : [];
      if (items.length) setAccountStates((previous) => mergeResultStates(previous, items));
      notify("MOMO 任务状态已刷新");
    } catch (error) { notify(error instanceof Error ? error.message : "任务刷新失败", "error"); }
  }

  function abandonRecovery() {
    setActiveTaskID("");
    setTask(null);
    setTaskAccounts([]);
    setAccountStates({});
    setTaskLogs([]);
    setWatchError("");
    setCheckoutBusy(false);
    notify("已停止恢复本地 MOMO 任务，可重新提交");
  }

  async function copyLink(value: string) {
    try { await navigator.clipboard.writeText(value); notify("MOMO 授权链接已复制"); }
    catch { notify("复制失败，请检查浏览器剪贴板权限", "error"); }
  }

  const progressCurrent = Number(task?.progress_detail?.current || 0);
  const progressTotal = Number(task?.progress_detail?.total || taskRows.length || 0);
  const progressPercent = progressTotal > 0 ? Math.min(100, Math.round(progressCurrent * 100 / progressTotal)) : 0;

  return <div className="gopay-view momo-payment-view">
    {notice && <div className={cn("gopay-toast", notice.type === "error" && "is-error")} role={notice.type === "error" ? "alert" : "status"} aria-live={notice.type === "error" ? "assertive" : "polite"}>
      {notice.type === "error" ? <XCircle /> : <CheckCircle2 />}{notice.text}
    </div>}

    <div className="gopay-section-title">
      <div><h2>MOMO 协议支付</h2><p>越南 MOMO 钱包 OAICS 授权链接批量提取</p></div>
      <span className={cn("paypal-active-count", checkoutBusy && "is-running")}>{checkoutBusy ? `${runningCount || taskRows.length} 个处理中` : task ? taskStatusLabel(task.status) : "未运行"}</span>
    </div>

    <section className="momo-stats" aria-label="MOMO 任务概览">
      <div><span><UsersRound />已导入 AT</span><strong>{accounts.length}</strong></div>
      <div><span><ShieldCheck />已选择</span><strong>{selectedAccounts.length}</strong></div>
      <div><span><Activity />进行中</span><strong>{runningCount}</strong></div>
      <div><span><Link2 />成功链接</span><strong>{successCount}</strong></div>
    </section>

    <div className="momo-setup-grid">
      <section className="gopay-panel">
        <header><h3>越南代理池</h3><span className="momo-meta">Checkout {proxyCount} · Promotion {promotionProxyCount}</span></header>
        <div className="momo-proxy-grid">
          <label><span>Checkout 代理池 · VN</span><textarea value={checkoutProxies} onChange={(event) => setCheckoutProxies(event.target.value)} rows={5} spellCheck={false} disabled={configBusy} placeholder="每行一个 HTTP、HTTPS 或 SOCKS5 代理" /></label>
          <label><span>Promotion 代理池 · VN</span><textarea value={promotionProxies} onChange={(event) => setPromotionProxies(event.target.value)} rows={5} spellCheck={false} disabled={configBusy} placeholder="每行一个 HTTP、HTTPS 或 SOCKS5 代理" /></label>
        </div>
      </section>

      <section className="gopay-panel">
        <header><h3>任务配置</h3><span className="momo-region-badge">VN · VND</span></header>
        <div className="momo-config-grid">
          <label><span>订阅套餐</span><select value={plan} onChange={(event) => setPlan(event.target.value)} disabled={configBusy}><option value="plus">ChatGPT Plus</option><option value="pro">ChatGPT Pro</option><option value="team">ChatGPT Team</option><option value="codex_low">Codex 空间</option></select></label>
          <label><span>提链并发</span><input type="number" min={1} max={100} value={concurrency} onChange={(event) => setConcurrency(clampNumber(event.target.value, 1, 1, 100))} disabled={configBusy} /></label>
          <label><span>失败重试</span><input type="number" min={0} max={50} value={retryCount} onChange={(event) => setRetryCount(clampNumber(event.target.value, 0, 0, 50))} disabled={configBusy} /></label>
          <label className="momo-promo-field"><span>Plus 优惠活动</span><input value={promoCampaign} onChange={(event) => setPromoCampaign(event.target.value)} disabled={configBusy || plan !== "plus" || !usePromo} /></label>
          <label className={cn("gopay-check momo-promo-toggle", (configBusy || plan !== "plus") && "is-disabled")}><input type="checkbox" checked={plan === "plus" && usePromo} disabled={configBusy || plan !== "plus"} onChange={(event) => setUsePromo(event.target.checked)} /><span><strong>应用 Plus 优惠</strong><small>协议流程会校验最终 VND 金额</small></span></label>
          {plan === "team" && <><label><span>空间名称</span><input value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} disabled={configBusy} /></label><label><span>已有空间 ID</span><input value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)} disabled={configBusy} /></label><label><span>席位数量</span><input type="number" min={2} max={100} value={seatQuantity} onChange={(event) => setSeatQuantity(clampNumber(event.target.value, 2, 2, 100))} disabled={configBusy} /></label><label><span>订阅周期</span><select value={priceInterval} onChange={(event) => setPriceInterval(event.target.value)} disabled={configBusy}><option value="month">按月</option><option value="year">按年</option></select></label></>}
          {plan === "codex_low" && <><label><span>空间名称</span><input value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} disabled={configBusy} /></label><label><span>积分数量</span><input type="number" min={1} max={10000} value={creditQuantity} onChange={(event) => setCreditQuantity(clampNumber(event.target.value, 1, 1, 10000))} disabled={configBusy} /></label></>}
        </div>
      </section>
    </div>

    <section className="gopay-panel">
      <header><h3>导入账户 AT</h3><span className="momo-meta">有效 {accounts.filter((item) => item.status === "ready").length} · 无效 {accounts.filter((item) => item.status !== "ready").length}</span></header>
      <div className="momo-import-area">
        <textarea aria-label="导入账户 Access Token" value={importText} onChange={(event) => setImportText(event.target.value)} rows={4} spellCheck={false} disabled={configBusy} placeholder="每行一个 Access Token，也支持包含 access_token 的 JSON / JSONL" />
        <div className="momo-import-actions">
          <Button size="sm" onClick={() => importAccounts(importText)} disabled={!importText.trim() || configBusy}><Upload className="mr-1 h-3.5 w-3.5" />导入列表</Button>
          <label className={cn("momo-file-button", configBusy && "is-disabled")} aria-disabled={configBusy}><FileUp />从文件导入<input type="file" accept=".txt,.json,.jsonl" onChange={(event) => void handleFile(event)} disabled={configBusy} /></label>
          <Button size="sm" variant="outline" onClick={removeSelectedAccounts} disabled={!selected.length || configBusy}><Trash2 className="mr-1 h-3.5 w-3.5" />删除选中</Button>
          <Button size="sm" variant="outline" onClick={() => { setExternalText(""); setSelected([]); setChecks({}); notify("AT 列表已清空"); }} disabled={!accounts.length || configBusy}>清空列表</Button>
        </div>
      </div>
      <div className="momo-selection-bar">
        <label className={cn(configBusy && "is-disabled")}><input type="checkbox" checked={accounts.some((item) => item.status === "ready") && selectedAccounts.length === accounts.filter((item) => item.status === "ready").length} onChange={(event) => setSelected(event.target.checked ? accounts.filter((item) => item.status === "ready").map((item) => item.index) : [])} disabled={configBusy} />选择全部有效 AT</label>
        <span>已选择 {selectedAccounts.length} / {accounts.length}</span>
      </div>
      <div className="gopay-table-wrap momo-at-table"><table aria-label="MOMO Access Token 列表"><thead><tr><th>选择</th><th>账户</th><th>AT 状态</th><th>试用资格</th><th>Checkout</th><th>支付方式</th><th>检测信息</th></tr></thead><tbody>{accounts.length ? accounts.map((account) => {
        const check = checks[String(account.index)] || {};
        const methods = Array.isArray(check.payment_methods) ? check.payment_methods.join(", ") : "";
        return <tr key={`${account.index}-${account.token.slice(-12)}`}><td><input type="checkbox" aria-label={`选择 ${account.email}`} checked={selected.includes(account.index)} disabled={account.status !== "ready" || configBusy} onChange={(event) => setSelected((current) => event.target.checked ? Array.from(new Set([...current, account.index])) : current.filter((item) => item !== account.index))} /></td><td><strong>{account.email}</strong><small className="momo-subtext">{account.expiresAt ? `到期 ${formatTime(account.expiresAt)}` : `AT ${account.index + 1}`}</small></td><td><span className={cn("gopay-status", account.status === "ready" ? "is-success" : "is-error")}>{account.status === "ready" ? "可用" : account.status === "expired" ? "已过期" : "格式无效"}</span></td><td>{check.trial_eligibility === "eligible" ? <span className="momo-positive">有试用</span> : check.trial_eligibility === "ineligible" ? "无试用" : "-"}</td><td>{check.checkout_kind ? String(check.checkout_kind).toUpperCase() : "-"}</td><td className="gopay-message" title={methods}>{methods || "-"}</td><td className="gopay-message" title={String(check.check_error || check.checkout_error || "")}>{check.check_error || check.checkout_error || (check.check_status === "checked" ? "检测通过" : "-")}</td></tr>;
      }) : <tr><td colSpan={7}><div className="gopay-empty"><WalletCards /><strong>暂无 MOMO 支付账户</strong><span>导入 AT 后即可检测并创建任务</span></div></td></tr>}</tbody></table></div>
    </section>

    <div className="momo-toolbar">
      <div className="momo-toolbar-status"><Gauge /><span><strong>{watchError ? "任务恢复异常" : task ? taskStatusLabel(task.status) : "等待任务"}</strong><small>{watchError || (task ? `任务 ${task.id} · ${task.progress || "0/0"}` : "VN / VND")}</small></span></div>
      <Button variant="outline" onClick={() => void precheck()} disabled={precheckBusy || checkoutBusy || !selectedAccounts.length}>{precheckBusy ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-1 h-4 w-4" />}{precheckBusy ? "检测中" : "检测资格 / Checkout"}</Button>
      <Button onClick={() => void startTask()} disabled={configBusy || !selectedAccounts.length}><Play className="mr-1 h-4 w-4" />开始 MOMO 任务</Button>
      <Button variant="outline" onClick={() => void cancelTask()} disabled={!task || task.terminal || cancelBusy}>{cancelBusy ? <Loader2 className="mr-1 h-4 w-4 animate-spin" /> : <Square className="mr-1 h-3.5 w-3.5" />}{cancelBusy ? "停止中" : "停止"}</Button>
      <Button variant="outline" onClick={() => void refreshTask()} disabled={!activeTaskID}><RefreshCw className="mr-1 h-4 w-4" />刷新状态</Button>
      {watchError && activeTaskID && <Button variant="outline" onClick={abandonRecovery}><XCircle className="mr-1 h-4 w-4" />放弃恢复</Button>}
    </div>

    {task && <section className="momo-task-progress" aria-label="MOMO 任务进度">
      <div><span><strong>{taskStatusLabel(task.status)}</strong><small>成功 {task.success ?? successCount} · 失败 {task.error_count ?? 0} · 更新 {formatTime(task.updated_at)}</small></span><b>{progressPercent}%</b></div>
      <div className="momo-progress-track" role="progressbar" aria-label="MOMO 批量任务进度" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progressPercent}><span style={{ width: `${progressPercent}%` }} /></div>
      {task.terminal && task.status !== "succeeded" && <p>{task.error || "任务已结束，请查看账户结果"}</p>}
    </section>}

    <section className="gopay-panel">
      <header><h3>MOMO 账户任务 · {taskRows.length}</h3><span className="momo-meta">成功 {successCount} · 进行中 {runningCount}</span></header>
      <div className="gopay-table-wrap"><table aria-label="MOMO 账户任务结果"><thead><tr><th>#</th><th>账户</th><th>当前步骤</th><th>进度</th><th>状态</th><th>金额</th><th>MOMO 授权链接</th><th>错误</th></tr></thead><tbody>{taskRows.length ? taskRows.map((row) => {
        const link = resultLink(row.result);
        const error = resultError(row.result);
        const rowProgress = Math.max(0, Math.min(100, row.progress));
        const expired = row.status === "succeeded" && resultExpired(row.result, clock);
        return <tr key={row.index}><td>{row.index + 1}</td><td><strong>{row.email || `账户 ${row.index + 1}`}</strong></td><td className="gopay-message" title={row.message}>{row.message}</td><td><div className="momo-row-progress" role="progressbar" aria-label={`${row.email || `账户 ${row.index + 1}`} 进度`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(rowProgress)}><span style={{ width: `${rowProgress}%` }} /><b>{Math.round(rowProgress)}%</b></div></td><td><span className={cn("gopay-status", expired || row.status === "failed" ? "is-error" : row.status === "succeeded" ? "is-success" : row.status === "cancelled" ? "is-cancelled" : row.status === "running" ? "is-running" : "is-idle")}>{expired ? "链接已过期" : accountStatusLabel(row.status)}</span></td><td>{formatAmount(row.result)}</td><td>{link ? expired ? <span className="momo-expired">请重新生成</span> : <div className="momo-link-actions"><button type="button" title="复制 MOMO 授权链接" onClick={() => void copyLink(link)}><Clipboard />复制</button><button type="button" title="打开 MOMO 授权链接" onClick={() => window.open(link, "_blank", "noopener,noreferrer")}><ExternalLink />打开</button></div> : "-"}</td><td className="gopay-message momo-error" title={error}>{error || "-"}</td></tr>;
      }) : <tr><td colSpan={8}><div className="gopay-empty"><Link2 /><strong>暂无 MOMO 任务</strong><span>选择账户并开始任务后显示逐账户进度</span></div></td></tr>}</tbody></table></div>
    </section>

    <section className="gopay-panel">
      <header><h3>实时协议日志</h3><span className="momo-meta">{taskLogs.length} 条</span></header>
      <div className="momo-log-list" role="log" aria-live="polite">{taskLogs.length ? taskLogs.map((entry, index) => {
        const level = entry.level === "error" ? "错误" : entry.level === "warning" ? "警告" : "信息";
        const message = String(entry.message || entry.detail?.current_log || entry.line || "-");
        return <div key={entry.id || index}><time>{String(entry.created_at || "").slice(11, 19) || "--:--:--"}</time><span aria-hidden="true" className={cn(entry.level === "error" ? "is-error" : entry.level === "warning" ? "is-warning" : "is-info")} /><p><span className="sr-only">{level}：</span>{message}</p></div>;
      }) : <div className="momo-log-empty">任务开始后显示协议执行日志</div>}</div>
    </section>
  </div>;
}
