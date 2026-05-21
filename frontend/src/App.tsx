import { useState } from "react";
import { LoginPage } from "./pages/Login";
import { RegisterPage } from "./pages/Register";
import { Dashboard } from "./pages/Dashboard";
import { OnboardingPage } from "./pages/OnboardingPage";
import type { AuthUser } from "./lib/api";

type AppView = "dashboard" | "onboarding";
type AuthView = "login" | "register";

function hasInviteInUrl(): boolean {
  const search = new URLSearchParams(window.location.search);
  if (search.get("invite_email")) return true;
  const hashIdx = window.location.hash.indexOf("?");
  if (hashIdx >= 0) {
    const hashSearch = new URLSearchParams(window.location.hash.slice(hashIdx + 1));
    if (hashSearch.get("invite_email")) return true;
  }
  return false;
}

export function App() {
  const [user, setUser] = useState<AuthUser | undefined>(undefined);
  const [view, setView] = useState<AppView>("dashboard");
  // 초대 URL이면 자동으로 register view로 진입.
  const [authView, setAuthView] = useState<AuthView>(hasInviteInUrl() ? "register" : "login");

  function handleLogin(authUser: AuthUser) {
    setUser(authUser);
    setView("dashboard");
  }

  function handleRegister(authUser: AuthUser) {
    // 새로 가입한 사용자는 onboarding으로 바로 이동.
    setUser(authUser);
    setView("onboarding");
  }

  function handleLogout() {
    setUser(undefined);
    setView("dashboard");
    setAuthView("login");
  }

  if (!user) {
    if (authView === "register") {
      return (
        <RegisterPage
          onRegister={handleRegister}
          onGoToLogin={() => setAuthView("login")}
        />
      );
    }
    return (
      <LoginPage
        onLogin={handleLogin}
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
