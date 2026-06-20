import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, UnauthorizedError, api, type Identity } from "@/lib/api";
import {
  approvalAuditHref,
  approvalRows,
  requesterMatchesPrincipal,
  type ApprovalQueueRow,
} from "@/lib/approvalQueue";
import { useAuth } from "@/auth/AuthProvider";
import { DataGrid, type DataGridColumn } from "@/components/DataGrid";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";

type Notice = { kind: "permission" | "error"; message: string };

export function Approvals() {
  const { user } = useAuth();
  const [identities, setIdentities] = useState<Identity[] | null>(null);
  const [error, setError] = useState<Notice | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const rows = useMemo(() => approvalRows(identities ?? []), [identities]);

  async function load() {
    setError(null);
    try {
      setIdentities(await api.identities());
    } catch (err) {
      setIdentities(null);
      setError(noticeForError(err));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function approve(row: ApprovalQueueRow) {
    const key = rowKey(row);
    setBusyKey(key);
    setError(null);
    setNotice(null);
    try {
      const result = await api.approveIdentityAction(row.identity.id, row.action);
      setNotice(`${result.action} approval recorded for ${result.resource} (${result.approvals})`);
      await load();
    } catch (err) {
      setError({ kind: "error", message: approvalErrorMessage(err) });
    } finally {
      setBusyKey(null);
    }
  }

  const columns = useMemo<Array<DataGridColumn<ApprovalQueueRow>>>(
    () => [
      {
        id: "resource",
        header: "Resource",
        sortable: true,
        cell: (row) => <span className="font-medium">{row.identity.name}</span>,
      },
      {
        id: "action",
        header: "Action",
        cell: (row) => <StatusBadge vocabulary="lifecycle" value={row.action === "issue" ? "requested" : "revoked"} label={row.action} />,
      },
      {
        id: "requester",
        header: "Requester",
        cell: (row) => row.requester,
      },
      {
        id: "quorum",
        header: "Quorum",
        cell: (row) => row.approvals,
      },
      {
        id: "grant",
        header: "Time-bound grant",
        cell: (row) => row.grantExpiresAt,
      },
      {
        id: "audit",
        header: "Evidence",
        cell: (row) => (
          <Link className="text-primary underline" to={approvalAuditHref(row)}>
            Audit trail
          </Link>
        ),
      },
      {
        id: "decision",
        header: "Decision",
        cell: (row) => {
          const selfApproval = requesterMatchesPrincipal(row, user);
          const describedBy = selfApproval ? `approval-disabled-${rowKey(row)}` : undefined;
          return (
            <div className="grid gap-1">
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={busyKey === rowKey(row) || selfApproval}
                aria-describedby={describedBy}
                onClick={() => void approve(row)}
              >
                {`Approve ${row.action} for ${row.identity.name}`}
              </Button>
              {selfApproval && (
                <p id={describedBy} className="max-w-xs text-xs text-muted-foreground">
                  Requesters cannot approve their own request; use a distinct approver.
                </p>
              )}
            </div>
          );
        },
      },
    ],
    [busyKey, user],
  );

  return (
    <section aria-labelledby="approvals-heading" className="space-y-5">
      <div>
        <h1 id="approvals-heading" className="text-2xl font-semibold">
          Approvals
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Dual-control issue and revoke decisions for a distinct approver. The queue is built from served identities; quorum and requester details appear when identity attributes carry them.
        </p>
      </div>

      {notice && <p role="status" className="text-sm text-status-success">{notice}</p>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Approvals unavailable">{error.message}</ErrorState>}
      {!identities && !error && <LoadingState>Loading approvals...</LoadingState>}
      {identities && rows.length === 0 && (
        <EmptyState title="No pending approvals">
          No served identities currently require an issue or revoke approval.
        </EmptyState>
      )}
      {identities && rows.length > 0 && (
        <DataGrid
          ariaLabel="Pending approvals"
          rows={rows}
          columns={columns}
          getRowId={rowKey}
        />
      )}
    </section>
  );
}

function rowKey(row: ApprovalQueueRow): string {
  return `${row.identity.id}:${row.action}`;
}

function noticeForError(err: unknown): Notice {
  if (err instanceof UnauthorizedError) {
    return { kind: "permission", message: "Your session cannot read tenant approval requests." };
  }
  return { kind: "error", message: apiProblemMessage(err, "Could not load approvals") };
}

function approvalErrorMessage(err: unknown): string {
  if (err instanceof ApiError && err.isRateLimited) {
    return err.retryAfterSeconds != null
      ? `Approval rate limited — please retry in ${err.retryAfterSeconds}s.`
      : "Approval rate limited — please retry shortly.";
  }
  return apiProblemMessage(err, "Approval failed");
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    try {
      const problem = JSON.parse(err.body) as { detail?: string; title?: string };
      return problem.detail || problem.title || err.message;
    } catch {
      return err.body || err.message;
    }
  }
  return err instanceof Error ? err.message : fallback;
}
