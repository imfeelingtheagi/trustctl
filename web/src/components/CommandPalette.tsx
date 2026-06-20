import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from "react";
import { Search, X } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { appRoutePaths, navGroups } from "@/lib/navigation";
import { useGlobalSearch, type GlobalSearchResult } from "@/lib/search";
import { cn } from "@/lib/utils";

interface RouteCommand {
  id: string;
  label: string;
  description: string;
  to: string;
}

export interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement>;
}

function titleFromPath(path: string): string {
  if (path === "/") return "Dashboard";
  return path
    .slice(1)
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function basePath(to: string): string {
  return to.split("?")[0] || "/";
}

function routeCommands(): RouteCommand[] {
  const labels = new Map<string, { label: string; group: string }>();
  for (const group of navGroups) {
    for (const item of group.items) {
      const path = basePath(item.to);
      if (!labels.has(path)) {
        labels.set(path, { label: item.label, group: group.label });
      }
    }
  }
  return appRoutePaths.map((path) => {
    const nav = labels.get(path);
    return {
      id: `route:${path}`,
      label: nav?.label ?? titleFromPath(path),
      description: `Route · ${nav?.group ?? path}`,
      to: path,
    };
  });
}

const commands = routeCommands();

function matchesRoute(command: RouteCommand, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [command.label, command.description, command.to].some((value) => value.toLowerCase().includes(needle));
}

function routeScore(command: RouteCommand, query: string): number {
  const needle = query.trim().toLowerCase();
  if (!needle) return 0;
  const label = command.label.toLowerCase();
  const to = command.to.toLowerCase();
  const description = command.description.toLowerCase();
  if (label === needle) return 0;
  if (label.startsWith(needle)) return 1;
  if (to.includes(needle)) return 2;
  if (description.includes(needle)) return 3;
  return 4;
}

function focusableElements(panel: HTMLElement): HTMLElement[] {
  return Array.from(
    panel.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
    ),
  );
}

export function CommandPalette({ open, onClose, returnFocusRef }: CommandPaletteProps) {
  const navigate = useNavigate();
  const panelRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const trimmed = query.trim();
  const search = useGlobalSearch(query, { enabled: open && trimmed.length > 0 });
  const filteredRoutes = useMemo(
    () =>
      commands
        .filter((command) => matchesRoute(command, query))
        .sort((left, right) => routeScore(left, query) - routeScore(right, query)),
    [query],
  );
  const choices: Array<RouteCommand | GlobalSearchResult> = [...filteredRoutes, ...search.results];
  const titleId = "command-palette-title";
  const descriptionId = "command-palette-description";

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    inputRef.current?.focus();
    return () => {
      setQuery("");
      const target = returnFocusRef?.current ?? previous;
      target?.focus();
    };
  }, [open, returnFocusRef]);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = focusableElements(panelRef.current);
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose, open]);

  if (!open) return null;

  function activate(target: RouteCommand | GlobalSearchResult) {
    navigate(target.to);
    onClose();
  }

  function onInputKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key !== "Enter") return;
    const target = choices[0];
    if (!target) return;
    event.preventDefault();
    activate(target);
  }

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-foreground/20" aria-hidden="true" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="absolute left-1/2 top-16 flex w-[min(42rem,calc(100vw-2rem))] -translate-x-1/2 flex-col overflow-hidden rounded-panel border border-border bg-background shadow-elevation3"
      >
        <div className="flex items-start justify-between gap-3 border-b border-border p-comfortable">
          <div>
            <h2 id={titleId} className="text-heading font-semibold">
              Command palette
            </h2>
            <p id={descriptionId} className="mt-1 text-sm text-muted-foreground">
              Jump to routes or search served certificate, identity, and secret metadata.
            </p>
          </div>
          <Button type="button" size="sm" variant="ghost" onClick={onClose}>
            <X className="h-4 w-4" aria-hidden="true" />
            <span>Close command palette</span>
          </Button>
        </div>
        <div className="border-b border-border p-comfortable">
          <label className="relative block">
            <Search
              aria-hidden="true"
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            />
            <input
              ref={inputRef}
              type="search"
              aria-label="Search routes and inventory"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder="Search routes, certificates, identities, or secrets"
              className="h-10 w-full rounded-md border border-border bg-background pl-9 pr-3 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </label>
          {search.unavailableSources.length > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              Some search sources are unavailable: {search.unavailableSources.join(", ")}.
            </p>
          )}
        </div>
        <div className="max-h-[24rem] overflow-y-auto p-2">
          {search.loading && <p className="px-3 py-2 text-sm text-muted-foreground">Searching served inventory...</p>}
          {filteredRoutes.length > 0 && (
            <PaletteSection title="Routes">
              {filteredRoutes.map((command) => (
                <PaletteButton key={command.id} label={command.label} description={command.description} onClick={() => activate(command)} />
              ))}
            </PaletteSection>
          )}
          {search.results.length > 0 && (
            <PaletteSection title="Inventory">
              {search.results.map((result) => (
                <PaletteButton
                  key={result.id}
                  label={result.label}
                  description={`${kindLabel(result.kind)} · ${result.description}`}
                  onClick={() => activate(result)}
                />
              ))}
            </PaletteSection>
          )}
          {!search.loading && choices.length === 0 && (
            <p className="px-3 py-6 text-center text-sm text-muted-foreground">No routes or inventory matched.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function PaletteSection({ children, title }: { children: ReactNode; title: string }) {
  return (
    <section className="py-1" aria-label={title}>
      <h3 className="px-3 py-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</h3>
      <div className="space-y-1">{children}</div>
    </section>
  );
}

function PaletteButton({
  description,
  label,
  onClick,
}: {
  description: string;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left text-sm",
        "hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring",
      )}
    >
      <span className="min-w-0">
        <span className="block truncate font-medium">{label}</span>
        <span className="block truncate text-xs text-muted-foreground">{description}</span>
      </span>
      <span className="shrink-0 text-xs text-muted-foreground">Enter</span>
    </button>
  );
}

function kindLabel(kind: GlobalSearchResult["kind"]): string {
  switch (kind) {
    case "certificate":
      return "Certificate";
    case "identity":
      return "Identity";
    case "secret":
      return "Secret";
  }
}
