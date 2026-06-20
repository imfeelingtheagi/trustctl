import { useEffect, useRef, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  Bot,
  Boxes,
  Braces,
  CircleHelp,
  FileClock,
  GitFork,
  LayoutDashboard,
  Menu,
  Network,
  RadioTower,
  ScrollText,
  Settings2,
  ShieldAlert,
  KeyRound,
  LockKeyhole,
  Rocket,
  ServerCog,
  Siren,
  Search,
  Users,
  X,
} from "lucide-react";
import { useAuth } from "@/auth/AuthProvider";
import { CommandPalette } from "@/components/CommandPalette";
import { ShortcutsHelp } from "@/components/ShortcutsHelp";
import { StatusBadge } from "@/components/StatusBadge";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Button } from "@/components/ui/button";
import {
  navGroups,
  navTreatmentForItem,
  taskNavItems,
  type NavIcon,
  type NavTreatment,
} from "@/lib/navigation";
import { cn } from "@/lib/utils";

const iconMap: Record<NavIcon, typeof Activity> = {
  activity: Activity,
  audit: FileClock,
  bot: Bot,
  certificate: ScrollText,
  connector: Boxes,
  dashboard: LayoutDashboard,
  graph: GitFork,
  identity: KeyRound,
  incident: Siren,
  key: LockKeyhole,
  owner: Users,
  platform: ServerCog,
  policy: Settings2,
  profile: Settings2,
  protocol: RadioTower,
  risk: ShieldAlert,
  rocket: Rocket,
  secret: KeyRound,
  spiffe: Network,
  ssh: Braces,
};

function NavTreatmentBadge({ treatment }: { treatment: NavTreatment }) {
  return (
    <StatusBadge
      vocabulary="honesty"
      value={treatment}
      className="min-h-5 shrink-0 rounded px-1.5 py-0 text-[10px] leading-5"
    />
  );
}

function useIsDesktop() {
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window === "undefined" ? true : window.innerWidth >= 768,
  );

  useEffect(() => {
    const updateWidth = () => setIsDesktop(window.innerWidth >= 768);
    updateWidth();
    window.addEventListener("resize", updateWidth);
    return () => window.removeEventListener("resize", updateWidth);
  }, []);

  return isDesktop;
}

type PrimaryNavProps = {
  className?: string;
  id?: string;
  onNavigate?: () => void;
};

function PrimaryNav({ className, id, onNavigate }: PrimaryNavProps) {
  return (
    <nav aria-label="Primary" className={cn("p-3", className)} id={id}>
      <ul className="space-y-4">
        <li>
          <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Needs action
          </p>
          <ul aria-label="Needs action worklists" className="space-y-1">
            {taskNavItems.map(({ to, label, description, icon, treatment }) => {
              const Icon = iconMap[icon];
              return (
                <li key={`task-${to}`}>
                  <NavLink
                    to={to}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        "flex min-h-12 items-start gap-2 rounded-md px-3 py-2 text-sm",
                        isActive ? "bg-muted font-medium" : "hover:bg-muted",
                      )
                    }
                  >
                    <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate">{label}</span>
                      <span className="block truncate text-xs font-normal text-muted-foreground">{description}</span>
                    </span>
                    <NavTreatmentBadge treatment={treatment} />
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </li>
        {navGroups.map((group) => (
          <li key={group.label}>
            <p className="px-3 pb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {group.label}
            </p>
            <ul className="space-y-1">
              {group.items.map((item) => {
                const { to, label, icon, end } = item;
                const Icon = iconMap[icon];
                const treatment = navTreatmentForItem(item);
                return (
                  <li key={`${group.label}-${to}-${label}`}>
                    <NavLink
                      to={to}
                      end={end}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        cn(
                          "flex min-h-9 items-center gap-2 rounded-md px-3 py-2 text-sm",
                          isActive ? "bg-muted font-medium" : "hover:bg-muted",
                        )
                      }
                    >
                      <Icon aria-hidden="true" className="h-4 w-4 shrink-0" />
                      <span className="min-w-0 flex-1 truncate">{label}</span>
                      <NavTreatmentBadge treatment={treatment} />
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </li>
        ))}
      </ul>
    </nav>
  );
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return target.isContentEditable || tag === "input" || tag === "textarea" || tag === "select";
}

/** AppShell is the authenticated layout: a skip link, a banner header, a
 * navigation sidebar, and the routed main content — landmarked and keyboard
 * navigable for WCAG 2.1 AA. */
export function AppShell() {
  const { user } = useAuth();
  const isDesktop = useIsDesktop();
  const commandButtonRef = useRef<HTMLButtonElement>(null);
  const shortcutsButtonRef = useRef<HTMLButtonElement>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const mobileNavId = "mobile-primary-nav";

  useEffect(() => {
    if (isDesktop) {
      setMobileNavOpen(false);
    }
  }, [isDesktop]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandPaletteOpen(true);
        return;
      }
      if (event.key === "?" && !isEditableTarget(event.target)) {
        event.preventDefault();
        setShortcutsOpen(true);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        Skip to main content
      </a>

      <header className="flex h-14 items-center justify-between border-b border-border px-4">
        <div className="flex min-w-0 items-center gap-2">
          {!isDesktop && (
            <button
              type="button"
              aria-controls={mobileNavId}
              aria-expanded={mobileNavOpen}
              aria-label={mobileNavOpen ? "Close primary navigation" : "Open primary navigation"}
              onClick={() => setMobileNavOpen((open) => !open)}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
            >
              {mobileNavOpen ? (
                <X aria-hidden="true" className="h-4 w-4" />
              ) : (
                <Menu aria-hidden="true" className="h-4 w-4" />
              )}
            </button>
          )}
          <span className="truncate text-base font-semibold">trstctl</span>
        </div>
        <div className="flex min-w-0 items-center gap-2">
          <Button
            ref={commandButtonRef}
            type="button"
            variant="outline"
            size="sm"
            aria-label="Open command palette"
            onClick={() => setCommandPaletteOpen(true)}
            className="hidden min-w-48 justify-between px-2 text-muted-foreground md:inline-flex"
          >
            <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
            <span className="min-w-0 flex-1 truncate text-left">Search or jump</span>
            <kbd className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px]">Cmd K</kbd>
          </Button>
          {user && (
            <div
              aria-label="Tenant context"
              className="hidden min-w-0 items-center gap-2 rounded-md border border-border px-2 py-1 text-xs lg:flex"
            >
              <span className="text-muted-foreground">Tenant</span>
              <strong className="max-w-32 truncate font-semibold">{user.tenant_id}</strong>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled
                aria-label="Tenant switcher blocked on BACKEND-TENANT-ADMIN"
                className="h-6 px-2 text-[11px]"
              >
                Switch blocked
              </Button>
              <span className="hidden text-[10px] uppercase text-muted-foreground xl:inline">BACKEND-TENANT-ADMIN</span>
            </div>
          )}
          <Button
            ref={shortcutsButtonRef}
            type="button"
            size="icon"
            variant="ghost"
            aria-label="Open keyboard shortcuts"
            onClick={() => setShortcutsOpen(true)}
          >
            <CircleHelp className="h-4 w-4" aria-hidden="true" />
          </Button>
          <ThemeToggle />
          {user && (
            <span className="hidden max-w-44 truncate text-sm text-muted-foreground sm:inline" data-testid="current-user">
              {user.email || user.subject}
            </span>
          )}
        </div>
      </header>

      {!isDesktop && mobileNavOpen && (
        <div className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm">
          <div
            aria-label="Primary navigation"
            aria-modal="true"
            className="h-full w-[min(20rem,calc(100vw-2rem))] overflow-y-auto border-r border-border bg-background shadow-xl"
            role="dialog"
          >
            <div className="flex h-14 items-center justify-between border-b border-border px-4">
              <span className="text-sm font-semibold">Navigation</span>
              <button
                type="button"
                aria-label="Close primary navigation"
                onClick={() => setMobileNavOpen(false)}
                className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-border bg-background text-foreground hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring"
              >
                <X aria-hidden="true" className="h-4 w-4" />
              </button>
            </div>
            <PrimaryNav id={mobileNavId} onNavigate={() => setMobileNavOpen(false)} />
          </div>
        </div>
      )}

      <div className="flex min-w-0">
        {isDesktop && (
          <PrimaryNav
            className="max-h-[calc(100vh-3.5rem)] w-72 shrink-0 overflow-y-auto border-r border-border"
            id="desktop-primary-nav"
          />
        )}

        <main id="main" className="min-w-0 flex-1 p-4 md:p-6" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      <CommandPalette
        open={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        returnFocusRef={commandButtonRef}
      />
      <ShortcutsHelp
        open={shortcutsOpen}
        onClose={() => setShortcutsOpen(false)}
        returnFocusRef={shortcutsButtonRef}
      />
    </div>
  );
}
