import { BrowserRouter, NavLink, useLocation } from "react-router-dom";
import { useCallback, useEffect, useRef, useState } from "react";
import { Languages, Link2, LogOut, Moon, Sun } from "lucide-react";
import { API, cn } from "@/lib/utils";
import { I18nProvider, useI18n } from "@/lib/i18n-context";
import { useTopBarGsap } from "@/lib/useSunnyGsap";
import { CachedPage } from "@/lib/page-cache";
import { usePageScrollCache, useVisitedPageKeys } from "@/lib/page-cache-hooks";
import SunnyRegister, { clearSunnyRegisterTaskHistory } from "@/pages/SunnyRegister";
import PublicLanding from "@/pages/PublicLanding";
import AuditLogPage from "@/pages/AuditLogPage";
import CheckoutManager from "@/pages/CheckoutManager";
import PaymentManagement from "@/pages/PaymentManagement";

function words(language: string) {
  return language === "en-US"
    ? { app: "SunnyRegister", sub: "GPT account registration manager", home: "Studio", settings: "Settings", loginTitle: "Welcome back", loginDesc: "Enter your administrator credentials.", user: "Username", pass: "Password", submit: "Sign in", checking: "Checking...", failed: "Login failed", loading: "Loading...", logout: "Sign out" }
    : { app: "SunnyRegister", sub: "GPT 账号注册与管理", home: "工作台", settings: "设置", loginTitle: "欢迎回来", loginDesc: "请输入管理员账号与密码。", user: "用户名", pass: "密码", submit: "登录", checking: "验证中...", failed: "登录失败", loading: "加载中...", logout: "退出登录" };
}

function TopBar({ theme, setTheme, onLogout }: { theme: string; setTheme: (v: string) => void; onLogout: () => Promise<void> }) {
  const { language, toggleLanguage } = useI18n();
  const c = words(language);
  const location = useLocation();
  const headerRef = useRef<HTMLElement | null>(null);
  useTopBarGsap(headerRef, `${location.pathname}:${language}`);
  const menus = language === "en-US"
    ? [["/", "Workbench"], ["/mailbox", "Mailbox"], ["/phone", "SMS"], ["/sub2api", "Reverse"], ["/proxy", "Proxy"], ["/session", "Account Management"], ["/checkout", "Checkout Links"], ["/payments", "Payments"], ["/audit", "Audit Logs"]]
    : [["/", "工作台"], ["/mailbox", "邮箱配置"], ["/phone", "接码配置"], ["/sub2api", "反代配置"], ["/proxy", "代理配置"], ["/session", "账户管理"], ["/checkout", "提链管理"], ["/payments", "支付管理"], ["/audit", "日志管理"]];
  const navClass = (active: boolean) => cn("inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-semibold transition-all", active ? "bg-[var(--accent)] text-white shadow-[var(--shadow-glow)]" : "text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]");
  return (
    <header ref={headerRef} className="sticky top-0 z-[300] border-b border-[var(--border)] bg-[var(--bg-base)]">
      <div className="app-shell mx-auto grid grid-cols-[1fr_auto] items-center gap-4 py-3 lg:grid-cols-[280px_minmax(0,1fr)_160px]">
        <div className="flex min-w-0 shrink-0 items-center gap-3 justify-self-start">
          <div className="brand-mark"><Link2 className="h-5 w-5" /></div>
          <div className="hidden sm:block"><div className="text-sm font-black tracking-tight text-[var(--text-primary)]">{c.app}</div><div className="text-xs text-[var(--text-muted)]">{c.sub}</div></div>
        </div>
        <nav className="hidden w-fit max-w-full justify-center overflow-x-auto rounded-full border border-[var(--border)] bg-[var(--chip-bg)] p-1 justify-self-center lg:flex">
          {menus.map(([to, label]) => {
            const active = to === "/" ? location.pathname === "/" : location.pathname.startsWith(to);
            return <NavLink key={to} to={to} data-sunny-nav-active={active ? "true" : undefined} className={() => navClass(active)}>{label}</NavLink>;
          })}
        </nav>
        <div className="flex shrink-0 items-center justify-end gap-2 justify-self-end">
          <button className="round-tool" onClick={() => setTheme(theme === "light" ? "dark" : "light")} title={theme}>{theme === "light" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}</button>
          <button className="round-tool min-w-12 px-3 text-xs font-bold" onClick={toggleLanguage}><Languages className="h-4 w-4" />{language === "zh-CN" ? "中" : "EN"}</button>
          <button className="round-tool" title={c.logout} aria-label={c.logout} onClick={onLogout}><LogOut className="h-4 w-4" /></button>
        </div>
      </div>
    </header>
  );
}

type ShellPage = "sunny" | "checkout" | "payments" | "audit";

function shellPage(pathname: string): ShellPage {
  if (pathname.startsWith("/audit")) return "audit";
  if (pathname.startsWith("/checkout")) return "checkout";
  if (pathname.startsWith("/payments")) return "payments";
  return "sunny";
}

function menuPage(pathname: string) {
  const segment = pathname.split("/").filter(Boolean)[0];
  return segment || "workbench";
}

function CachedShellPages() {
  const location = useLocation();
  const activePage = shellPage(location.pathname);
  const visitedPages = useVisitedPageKeys(activePage);
  usePageScrollCache(menuPage(location.pathname));

  return (
    <main className="app-shell mx-auto py-6 md:py-8">
      <CachedPage active={activePage === "sunny"}>{visitedPages.has("sunny") && <SunnyRegister />}</CachedPage>
      <CachedPage active={activePage === "checkout"}>{visitedPages.has("checkout") && <CheckoutManager />}</CachedPage>
      <CachedPage active={activePage === "payments"}>{visitedPages.has("payments") && <PaymentManagement />}</CachedPage>
      <CachedPage active={activePage === "audit"}>{visitedPages.has("audit") && <AuditLogPage />}</CachedPage>
    </main>
  );
}

function Shell({ theme, setTheme, onLogout }: { theme: string; setTheme: (v: string) => void; onLogout: () => Promise<void> }) {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-[var(--bg-base)]">
        <TopBar theme={theme} setTheme={setTheme} onLogout={onLogout} />
        <CachedShellPages />
      </div>
    </BrowserRouter>
  );
}

function AppContent() {
  const { language } = useI18n();
  const c = words(language);
  const [theme, setTheme] = useState(() => localStorage.getItem("theme") === "dark" ? "dark" : "light");
  const [authState, setAuthState] = useState<"loading" | "open" | "locked" | "authed">("loading");
  const [logoutNotice, setLogoutNotice] = useState(false);
  useEffect(() => { document.documentElement.classList.toggle("light", theme === "light"); localStorage.setItem("theme", theme); }, [theme]);
  useEffect(() => { fetch(API + "/auth/check", { credentials: "include", cache: "no-store" }).then((r) => r.json()).then((data) => { if (!data.required) setAuthState("open"); else if (data.authenticated) setAuthState("authed"); else setAuthState("locked"); }).catch(() => setAuthState("locked")); }, []);
  const logout = useCallback(async () => {
    let completed = false;
    try {
      const response = await fetch(API + "/auth/logout", { method: "POST", credentials: "include", cache: "no-store" });
      completed = response.ok;
    } finally {
      window.history.replaceState(null, "", "/");
      setAuthState("locked");
      setLogoutNotice(completed);
    }
  }, []);
  if (authState === "loading") return <div className="flex h-screen items-center justify-center bg-[var(--bg-base)] text-sm text-[var(--text-muted)]">{c.loading}</div>;
  if (authState === "locked") return <PublicLanding onLogin={() => { clearSunnyRegisterTaskHistory(); setLogoutNotice(false); setAuthState("authed"); }} logoutNotice={logoutNotice} onNoticeDone={() => setLogoutNotice(false)} />;
  return <Shell theme={theme} setTheme={setTheme} onLogout={logout} />;
}

export default function App() { return <I18nProvider><AppContent /></I18nProvider>; }
