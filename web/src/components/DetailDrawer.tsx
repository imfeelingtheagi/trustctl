import { useEffect, useRef, type ReactNode, type RefObject } from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type DetailDrawerProps = {
  open: boolean;
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement>;
  className?: string;
};

export function DetailDrawer({ open, title, description, children, actions, onClose, returnFocusRef, className }: DetailDrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const titleId = "detail-drawer-title";
  const descriptionId = description ? "detail-drawer-description" : undefined;

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const returnTarget = returnFocusRef?.current ?? previous;
    closeRef.current?.focus();
    return () => {
      returnTarget?.focus();
    };
  }, [open, returnFocusRef]);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab" || !panelRef.current) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
      );
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

  return (
    <div className="fixed inset-0 z-50" role="presentation">
      <button type="button" aria-label="Close detail drawer" className="absolute inset-0 h-full w-full bg-foreground/20" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className={cn("absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-border bg-background shadow-elevation3", className)}
      >
        <header className="border-b border-border p-comfortable">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id={titleId} className="text-heading font-semibold">
                {title}
              </h2>
              {description && (
                <p id={descriptionId} className="mt-1 text-body text-muted-foreground">
                  {description}
                </p>
              )}
            </div>
            <Button ref={closeRef} type="button" size="sm" variant="ghost" onClick={onClose}>
              <X className="h-4 w-4" aria-hidden="true" />
              Close
            </Button>
          </div>
          {actions && <div className="mt-3 flex flex-wrap gap-2">{actions}</div>}
        </header>
        <div className="min-h-0 flex-1 overflow-y-auto p-comfortable">{children}</div>
      </div>
    </div>
  );
}
