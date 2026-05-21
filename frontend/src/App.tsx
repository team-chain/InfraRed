import { useState } from "react";
import { LoginPage } from "./pages/Login";
import { RegisterPage } from "./pages/Register";
import { Dashboard } from "./pages/Dashboard";
import { OnboardingPage } from "./pages/OnboardingPage";
import { VerifyEmailPage } from "./pages/VerifyEmail";
import { ForgotPasswordPage } from "./pages/ForgotPassword";
import { ResetPasswordPage } from "./pages/ResetPassword";
import type { AuthUser } from "./lib/api";

type AppView = "dashboard" | "onboarding";
type AuthView = "login" | "register" | "forgot" | "verify_email" | "reset_password";

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
  return "login";
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
  const [user, setUser] = useState<AuthUser | undefined>(undefined);
  const [view, setView] = useState<AppView>("dashboard");
  const [authView, setAuthView] = useState<AuthView>(initialAuthView);

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
    return (
      <LoginPage
        onLogin={handleLogin}
        onGoToRegister={() => setAuthView("register")}
        onForgotPassword={() => setAuthView("forgot")}
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
