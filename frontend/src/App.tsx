import { useMemo, useState } from "react";
import { LoginPage } from "./pages/Login";
import { RegisterPage } from "./pages/Register";
import { Dashboard } from "./pages/Dashboard";
import type { AuthUser } from "./lib/api";

const TOKEN_KEY = "infrared.accessToken";
const USER_KEY = "infrared.user";

type Page = "login" | "register";

export function App() {
  const [page, setPage] = useState<Page>("login");
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) ?? "");
  const [user, setUser] = useState<AuthUser | undefined>(() => {
    const raw = localStorage.getItem(USER_KEY);
    if (!raw) return undefined;
    try {
      return JSON.parse(raw) as AuthUser;
    } catch {
      localStorage.removeItem(USER_KEY);
      localStorage.removeItem(TOKEN_KEY);
      return undefined;
    }
  });

  const isAuthenticated = useMemo(() => Boolean(token && user), [token, user]);

  function handleAuth(accessToken: string, authUser: AuthUser) {
    localStorage.setItem(TOKEN_KEY, accessToken);
    localStorage.setItem(USER_KEY, JSON.stringify(authUser));
    setToken(accessToken);
    setUser(authUser);
  }

  function handleLogout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setToken("");
    setUser(undefined);
    setPage("login");
  }

  if (!isAuthenticated || !user) {
    if (page === "register") {
      return (
        <RegisterPage
          onRegister={handleAuth}
          onGoToLogin={() => setPage("login")}
        />
      );
    }
    return (
      <LoginPage
        onLogin={handleAuth}
        onGoToRegister={() => setPage("register")}
      />
    );
  }

  return <Dashboard token={token} user={user} onLogout={handleLogout} />;
}
