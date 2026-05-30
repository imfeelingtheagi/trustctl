import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useResource } from "@/lib/useResource";
import { EmptyState } from "@/components/EmptyState";

export function Certificates() {
  const { data, loading, error } = useResource(api.certificates);
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const all = data ?? [];
    const q = query.trim().toLowerCase();
    if (!q) return all;
    return all.filter((c) =>
      [c.subject, c.issuer, c.status].filter(Boolean).some((v) => v!.toLowerCase().includes(q)),
    );
  }, [data, query]);

  return (
    <section aria-labelledby="certs-heading">
      <h1 id="certs-heading" className="mb-4 text-2xl font-semibold">
        Certificates
      </h1>

      {loading && <p role="status">Loading certificates…</p>}
      {error && <p role="alert">Could not load certificates: {error}</p>}

      {data && data.length === 0 && (
        <EmptyState
          title="No certificates yet"
          ctaTo="/wizard"
          ctaLabel="Set up your first certificate"
        >
          Run the setup wizard to connect a CA, install an agent, and issue your first certificate.
        </EmptyState>
      )}

      {data && data.length > 0 && (
        <>
          <div className="mb-4 max-w-sm">
            <label htmlFor="cert-search" className="sr-only">
              Search certificates
            </label>
            <input
              id="cert-search"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by subject, issuer, or status…"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
          </div>

          {filtered.length === 0 ? (
            <p className="text-sm text-muted-foreground">No certificates match your search.</p>
          ) : (
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Inventoried certificates</caption>
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th scope="col" className="py-2 pr-4 font-medium">Subject</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Issuer</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Expires</th>
                  <th scope="col" className="py-2 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => (
                  <tr key={c.id} className="border-b border-border">
                    <td className="py-2 pr-4">{c.subject}</td>
                    <td className="py-2 pr-4">{c.issuer ?? "—"}</td>
                    <td className="py-2 pr-4">
                      {c.not_after ? new Date(c.not_after).toLocaleDateString() : "—"}
                    </td>
                    <td className="py-2">{c.status ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </section>
  );
}
