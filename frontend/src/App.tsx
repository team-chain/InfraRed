import { useState } from "react";
import { LoginPage } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import type { AuthUser } from "./lib/api";

export function App() {
  const [user, setUser] = useState<AuthUser | undefined>(undefined);

  function handleLogin(authUser: AuthUser) {
    setUser(authUser);
  }

  function handleLogout() {
    setUser(undefined);
  }

  if (!user) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return <Dashboard user={user} onLogout={handleLogout} />;
}
