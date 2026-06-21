import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, LoadingState } from "@/components/StatePrimitives";

export function Owners() {
  const { data, loading, error } = useResource(api.owners);
  return (
    <section aria-labelledby="owners-heading">
      <PageHeader titleId="owners-heading" title="Owners" />
      {loading && <LoadingState>Loading owners…</LoadingState>}
      {error && <ErrorState title="Could not load owners">{error}</ErrorState>}
      {data && (
        <table className="ui-table">
          <caption className="sr-only">Credential owners</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Kind</th>
              <th scope="col">Email</th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 && (
              <tr>
                <td colSpan={3} className="text-muted-foreground">
                  No owners yet.
                </td>
              </tr>
            )}
            {data.map((o) => (
              <tr key={o.id}>
                <td>{o.name}</td>
                <td>{o.kind}</td>
                <td>{o.email ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
