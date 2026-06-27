import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { ToastProvider } from "@/components/ToastProvider";
import { Notifications } from "@/pages/Notifications";

const { apiMock } = vi.hoisted(() => ({
  apiMock: {
    notifications: vi.fn(),
    markNotificationRead: vi.fn(),
    requeueNotification: vi.fn(),
  },
}));

vi.mock("@/lib/api", async (orig) => {
  const actual = await orig<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, ...apiMock } };
});

const pendingNotification = {
  id: "101",
  tenant_id: "t1",
  destination: "notification.email",
  kind: "certificate.expiring",
  certificate_id: "cert-pay",
  subject: "payments-api",
  detail: "Certificate expires in 7 days.",
  severity: "warning",
  status: "pending",
  attempts: 1,
  created_at: "2026-06-26T10:00:00Z",
};

const deadNotification = {
  id: "202",
  tenant_id: "t1",
  destination: "notification.webhook",
  kind: "webhook.delivery",
  subject: "billing-hook",
  detail: "Webhook failed after retries.",
  severity: "critical",
  status: "dead",
  attempts: 10,
  last_error: "POST 500",
  created_at: "2026-06-26T09:45:00Z",
};

function renderNotifications() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <Notifications />
      </ToastProvider>
    </MemoryRouter>,
  );
}

describe("C10-3 notifications inbox", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    for (const mock of Object.values(apiMock)) mock.mockReset();
    apiMock.notifications.mockImplementation((options?: { status?: string }) =>
      Promise.resolve({
        items: options?.status === "dead" ? [deadNotification] : [pendingNotification],
      }),
    );
    apiMock.markNotificationRead.mockResolvedValue({ ...pendingNotification, status: "read", read_at: "2026-06-26T10:05:00Z" });
    apiMock.requeueNotification.mockResolvedValue({ ...deadNotification, status: "pending", attempts: 0, last_error: undefined });
  });

  it("lists notifications, triages dead letters, marks read, requeues, and emits toasts", async () => {
    const user = userEvent.setup();
    renderNotifications();

    expect(await screen.findByRole("heading", { name: "Notifications" })).toBeInTheDocument();
    await waitFor(() => expect(apiMock.notifications).toHaveBeenCalledWith({ limit: 100 }));

    expect(screen.getByText("1 unread")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Type filter" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Status filter" })).toBeInTheDocument();

    const inboxRow = screen.getByText("payments-api").closest("tr")!;
    expect(within(inboxRow).getByText("certificate.expiring")).toBeInTheDocument();
    expect(within(inboxRow).getByText("1 / 10")).toBeInTheDocument();

    await user.click(within(inboxRow).getByRole("button", { name: "Mark notification 101 read" }));
    await waitFor(() => expect(apiMock.markNotificationRead).toHaveBeenCalledWith("101"));
    expect(await screen.findByRole("status", { name: "Notification marked read" })).toBeInTheDocument();
    expect(within(inboxRow).getByText("read")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Dead-letter" }));
    await waitFor(() => expect(apiMock.notifications).toHaveBeenCalledWith({ limit: 100, status: "dead" }));
    const deadRow = await screen.findByText("billing-hook");
    const deadLetterRow = deadRow.closest("tr")!;
    expect(within(deadLetterRow).getByText("dead")).toBeInTheDocument();
    expect(within(deadLetterRow).getByText("10 / 10")).toBeInTheDocument();
    expect(within(deadLetterRow).getByText("POST 500")).toBeInTheDocument();

    await user.click(within(deadLetterRow).getByRole("button", { name: "Requeue notification 202" }));
    await waitFor(() => expect(apiMock.requeueNotification).toHaveBeenCalledWith("202"));
    expect(await screen.findByRole("status", { name: "Notification requeued" })).toBeInTheDocument();
  });
});
