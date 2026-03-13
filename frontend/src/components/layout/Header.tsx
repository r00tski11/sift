import { useLocation } from "react-router-dom";
import { Sun, Moon } from "lucide-react";
import { useTheme } from "@/hooks/useTheme";
import { useAuthStore } from "@/stores/auth";
import { Button } from "@/components/ui/button";

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/projects": "Projects",
  "/scans/new": "New Scan",
  "/settings": "Settings",
};

function getPageTitle(pathname: string): string {
  if (pageTitles[pathname]) return pageTitles[pathname];
  if (pathname.startsWith("/projects/")) return "Project Details";
  if (pathname.startsWith("/scans/")) return "Scan Results";
  return "iOS Security Platform";
}

export function Header() {
  const { pathname } = useLocation();
  const { theme, toggleTheme } = useTheme();
  const { user } = useAuthStore();

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-border bg-card/80 px-6 backdrop-blur-sm">
      <h2 className="text-lg font-semibold text-foreground">
        {getPageTitle(pathname)}
      </h2>

      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={toggleTheme}>
          {theme === "dark" ? (
            <Sun className="h-5 w-5" />
          ) : (
            <Moon className="h-5 w-5" />
          )}
        </Button>

        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/20 text-sm font-medium text-primary">
            {user?.username?.charAt(0).toUpperCase() || "U"}
          </div>
          <span className="text-sm font-medium text-foreground">
            {user?.username || "User"}
          </span>
        </div>
      </div>
    </header>
  );
}
