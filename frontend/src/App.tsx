import { useState } from "react";
import { LoginPage } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { OnboardingPage } from "./pages/OnboardingPage";
import type { AuthUser } from "./lib/api";

type AppView = "dashboard" | "onboarding";

export function App() {
  const [user, setUser] = useState<AuthUser | undefined>(undefined);
  const [view, setView] = useState<AppView>("dashboard");

  function handleLogin(authUser: AuthUser) {
    setUser(authUser);
    setView("dashboard");
  }

  function handleLogout() {
    setUser(undefined);
    setView("dashboard");
  }

  if (!user) {
    return <LoginPage onLogin={handleLogin} />;
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
