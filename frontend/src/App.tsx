import { useState } from "react";
import { LoginPage } from "./pages/Login";
import { RegisterPage } from "./pages/Register";
import { Dashboard } from "./pages/Dashboard";
import { OnboardingPage } from "./pages/OnboardingPage";
import { VerifyEmailPage } from "./pages/VerifyEmail";
import { ForgotPasswordPage } from "./pages/ForgotPassword";
import { ResetPasswordPage } from "./pages/ResetPassword";
import { LandingPage } from "./pages/LandingPage";
import { StatusPage } from "./pages/StatusPage";
import type { AuthUser } from "./lib/api";

type AppView = "dashboard" | "onboarding";
type AuthView = "landing" | "login" | "register" | "forgot" | "verify_email" | "reset_password";

function getUrlParam(key: string): string | null {
  const search = new URLSearchParams(window.location.search);
  const v = search.get(key);
  if (v) return v;
  const hashIdx = window.location.hash.indexOf("?");
  if (hashIdx >= 0) {
    const hashSearch = new URLSearchParams(window.location.hash.slice(hashIdx + 1));
    return hashSearch.get(key);
  }
  return null;
}

function initialAuthView(): AuthView {
  if (getUrlParam("verify_email")) return "verify_email";
  if (getUrlParam("reset_token")) return "reset_password";
  if (getUrlParam("invite_email")) return "register";
  // 명시적으로 /login 경로 또는 ?view=login 파라미터로 직접 진입 시
  const path = typeof window !== "undefined" ? window.location.pathname : "";
  const viewParam = getUrlParam("view");
  if (path === "/login" || viewParam === "login") return "login";
  if (path === "/register" || viewParam === "register") return "register";
  return "landing";
}

function clearUrlParams() {
  if (typeof window === "undefined") return;
  // 토큰이 URL에 남으면 보안상 위험 — 처리 후 즉시 제거
  const url = new URL(window.location.href);
  ["verify_email", "reset_token", "invite_email", "tenant_id", "role"].forEach((k) => {
    url.searchParams.delete(k);
  });
  window.history.replaceState({}, "", url.toString());
}

export function App() {
  // hooks 먼저 모두 호출 (React rules of hooks)
  const [user, setUser] = useState<AuthUser | undefined>(undefined);
  const [view, setView] = useState<AppView>("dashboard");
  const [authView, setAuthView] = useState<AuthView>(initialAuthView);

  // /status 는 인증 여부와 무관하게 항상 공개
  const path = typeof window !== "undefined" ? window.location.pathname : "";
  if (path === "/status" || path.startsWith("/status/")) {
    return <StatusPage />;
  }

  // URL 파라미터에서 토큰 추출 (page에 props로 전달)
  const verifyToken = getUrlParam("verify_email");
  const resetToken = getUrlParam("reset_token");

  function handleLogin(authUser: AuthUser) {
    setUser(authUser);
    setView("dashboard");
  }

  function handleRegister(authUser: AuthUser) {
    setUser(authUser);
    setView("onboarding");
  }

  function handleLogout() {
    setUser(undefined);
    setView("dashboard");
    setAuthView("login");
  }

  function goToLogin() {
    clearUrlParams();
    setAuthView("login");
  }

  if (!user) {
    if (authView === "verify_email" && verifyToken) {
      return <VerifyEmailPage token={verifyToken} onDone={goToLogin} />;
    }
    if (authView === "reset_password" && resetToken) {
      return <ResetPasswordPage token={resetToken} onDone={goToLogin} />;
    }
    if (authView === "forgot") {
      return <ForgotPasswordPage onGoToLogin={goToLogin} />;
    }
    if (authView === "register") {
      return (
        <RegisterPage
          onRegister={handleRegister}
          onGoToLogin={goToLogin}
        />
      );
    }
    if (authView === "login") {
      return (
        <LoginPage
          onLogin={handleLogin}
          onGoToRegister={() => setAuthView("register")}
          onForgotPassword={() => setAuthView("forgot")}
        />
      );
    }
    return (
      <LandingPage
        onGoToLogin={() => setAuthView("login")}
        onGoToRegister={() => setAuthView("register")}
      />
    );
  }

  if (view === "onboarding") {
    return (
      <OnboardingPage
        tenantId={user.tenant_id}
        onDone={() => setView("dashboard")}
      />
    );
  }

  return (
    <Dashboard
      user={user}
      onLogout={handleLogout}
      onOpenOnboarding={() => setView("onboarding")}
    />
  );
}
