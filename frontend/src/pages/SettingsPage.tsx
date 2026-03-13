import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/stores/auth";
import { useTheme } from "@/hooks/useTheme";
import { Sun, Moon } from "lucide-react";

export function SettingsPage() {
  const { user } = useAuthStore();
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Profile */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Profile</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary/20 text-2xl font-bold text-primary">
              {user?.username?.charAt(0).toUpperCase() || "U"}
            </div>
            <div>
              <p className="text-lg font-semibold text-foreground">
                {user?.username || "User"}
              </p>
              <p className="text-sm text-muted-foreground">
                {user?.email || ""}
              </p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4 rounded-md bg-muted/50 p-4">
            <div>
              <p className="text-xs font-medium text-muted-foreground">
                Member since
              </p>
              <p className="text-sm text-foreground">
                {user?.created_at
                  ? new Date(user.created_at).toLocaleDateString()
                  : "-"}
              </p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground">
                Status
              </p>
              <p className="text-sm text-foreground">
                Active
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Appearance */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Appearance</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-foreground">Dark Mode</p>
              <p className="text-xs text-muted-foreground">
                Toggle between light and dark theme
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={toggleTheme}>
              {theme === "dark" ? (
                <>
                  <Sun className="mr-2 h-4 w-4" />
                  Light Mode
                </>
              ) : (
                <>
                  <Moon className="mr-2 h-4 w-4" />
                  Dark Mode
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
