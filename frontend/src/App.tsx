import { useState, useEffect } from "react";
import { LoginPage } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { OnboardingPage } from "./pages/OnboardingPage";
import type { AuthUser } from "./lib/api";
import { fetchMe } from "./lib/api";

type AppView = "dashboard" | "onboarding";

export function App() {
  const [user, setUser] = useState<AuthUser | undefined>(undefined);
  const [view, setView] = useState<AppView>("dashboard");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMe()
      .then((me) => {
        if (me) setUser(me);
      })
      .finally(() => setLoading(false));
  }, []);

  function handleLogin(authUser: AuthUser) {
    setUser(authUser);
    setView("dashboard");
  }

  function handleLogout() {
    setUser(undefined);
    setView("dashboard");
  }

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#0f172a", color: "#94a3b8", fontSize: 16 }}>
        Loading...
      </div>
    );
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
