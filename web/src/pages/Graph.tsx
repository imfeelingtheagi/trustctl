import { useEffect, useMemo, useState } from "react";
import {
  api,
  ApiError,
  type GraphImpact,
  type GraphNode,
  type GraphQueryResult,
  type GraphReachable,
  type GraphResponse,
} from "@/lib/api";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState, LoadingState, PermissionDeniedState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Notice = { kind: "permission" | "error"; message: string };

export function Graph() {
  const [graph, setGraph] = useState<{ data: GraphResponse | null; loading: boolean; error: Notice | null }>({
    data: null,
    loading: true,
    error: null,
  });
  const [selected, setSelected] = useState("");
  const [search, setSearch] = useState("");
  const [kindFilter, setKindFilter] = useState("all");
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [reachable, setReachable] = useState<GraphReachable | null>(null);
  const [queryText, setQueryText] = useState('MATCH (a)-[e]->(b) RETURN a,b');
  const [queryResult, setQueryResult] = useState<GraphQueryResult | null>(null);
  const [blastError, setBlastError] = useState<string | null>(null);
  const [reachableError, setReachableError] = useState<string | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"blast" | "reachable" | "query" | null>(null);
  const { data, loading, error } = graph;

  const nodeByID = useMemo(() => new Map((data?.nodes ?? []).map((node) => [node.id, node])), [data]);
  const kinds = useMemo(() => Array.from(new Set((data?.nodes ?? []).map((node) => node.kind))).sort(), [data]);
  const filteredNodes = useMemo(() => {
    const q = search.trim().toLowerCase();
    return (data?.nodes ?? []).filter((node) => {
      const kindOK = kindFilter === "all" || node.kind === kindFilter;
      const searchOK =
        !q ||
        node.id.toLowerCase().includes(q) ||
        node.name.toLowerCase().includes(q) ||
        node.kind.toLowerCase().includes(q) ||
        JSON.stringify(node.attrs ?? {}).toLowerCase().includes(q);
      return kindOK && searchOK;
    });
  }, [data, kindFilter, search]);
  const selectedNode = selected ? nodeByID.get(selected) ?? null : null;
  const emptyGraph = data != null && data.nodes.length === 0 && data.edges.length === 0;

  useEffect(() => {
    let active = true;
    api
      .graph()
      .then((result) => active && setGraph({ data: result, loading: false, error: null }))
      .catch((err) => active && setGraph({ data: null, loading: false, error: noticeFor(err, "Could not load graph") }));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (data?.nodes?.[0] && (!selected || !nodeByID.has(selected))) setSelected(data.nodes[0].id);
  }, [data, nodeByID, selected]);

  async function runBlastRadius() {
    if (!selected) return;
    setBusy("blast");
    setBlastError(null);
    try {
      const result = await api.graphBlastRadius(selected);
      setImpact(result);
    } catch (err) {
      setBlastError(apiProblemMessage(err, "Could not compute blast radius"));
    } finally {
      setBusy(null);
    }
  }

  async function runReachable() {
    if (!selected) return;
    setBusy("reachable");
    setReachableError(null);
    try {
      setReachable(await api.graphReachable(selected));
    } catch (err) {
      setReachableError(apiProblemMessage(err, "Could not compute reachability"));
    } finally {
      setBusy(null);
    }
  }

  async function runGraphQuery() {
    const query = queryText.trim();
    if (!query) return;
    setBusy("query");
    setQueryError(null);
    try {
      setQueryResult(await api.graphQuery(query));
    } catch (err) {
      setQueryError(apiProblemMessage(err, "Could not run graph query"));
    } finally {
      setBusy(null);
    }
  }

  return (
    <section aria-labelledby="graph-heading">
      <h1 id="graph-heading" className="mb-4 text-2xl font-semibold">
        Graph
      </h1>

      {loading && <LoadingState>Loading graph...</LoadingState>}
      {error?.kind === "permission" && <PermissionDeniedState>{error.message}</PermissionDeniedState>}
      {error?.kind === "error" && <ErrorState title="Graph unavailable">{error.message}</ErrorState>}

      {data && (
        <>
          <div className="mb-5 grid gap-4 sm:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle>Nodes</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold">{data.nodes.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Edges</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold">{data.edges.length}</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Blast radius</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-3xl font-semibold" data-testid="blast-radius-count">
                  {impact?.affected.length ?? "-"}
                </p>
              </CardContent>
            </Card>
          </div>

          {emptyGraph && (
            <EmptyState title="No graph nodes yet" ctaTo="/certificates" ctaLabel="Open certificate inventory">
              The served graph API returned no nodes or edges for this tenant. Ingest certificates or issue identities first.
            </EmptyState>
          )}

          <section aria-labelledby="graph-controls" className="my-5 rounded-md border border-border p-4">
            <h2 id="graph-controls" className="mb-3 text-sm font-semibold">
              Explore nodes
            </h2>
            <div className="grid gap-3 md:grid-cols-3">
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-search">
                Search
                <input
                  id="graph-search"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2"
                  placeholder="name, id, kind, attribute"
                />
              </label>
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-kind">
                Kind
                <select
                  id="graph-kind"
                  value={kindFilter}
                  onChange={(e) => setKindFilter(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2"
                >
                  <option value="all">All kinds</option>
                  {kinds.map((kind) => (
                    <option key={kind} value={kind}>
                      {kind}
                    </option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-node">
                Selected node
                <select
                  id="graph-node"
                  value={selected}
                  onChange={(e) => setSelected(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2"
                >
                  {data.nodes.map((node) => (
                    <option key={node.id} value={node.id}>
                      {node.name || node.id}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <Button type="button" disabled={busy === "blast" || !selected} onClick={() => void runBlastRadius()}>
                Analyze
              </Button>
              <Button type="button" variant="outline" disabled={busy === "reachable" || !selected} onClick={() => void runReachable()}>
                Show reachable
              </Button>
            </div>
          </section>

          {blastError && <ErrorState title="Blast radius unavailable">{blastError}</ErrorState>}
          {reachableError && <ErrorState title="Reachability unavailable">{reachableError}</ErrorState>}

          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_22rem]">
            <div className="space-y-5">
              <table className="w-full text-left text-sm">
            <caption className="sr-only">Credential graph nodes</caption>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                <th scope="col" className="py-2 pr-4 font-medium">Name</th>
                <th scope="col" className="py-2 pr-4 font-medium">Kind</th>
                <th scope="col" className="py-2 pr-4 font-medium">ID</th>
                <th scope="col" className="py-2 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredNodes.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-4 text-muted-foreground">No graph nodes match the current filters.</td>
                </tr>
              )}
              {filteredNodes.map((node) => (
                <tr key={node.id} className="border-b border-border">
                  <td className="py-2 pr-4" data-testid="graph-node-name">{node.name || "-"}</td>
                  <td className="py-2 pr-4">{node.kind}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{node.id}</td>
                  <td className="py-2">
                    <Button type="button" size="sm" variant="outline" onClick={() => setSelected(node.id)}>
                      Select {node.name || node.id}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
              </table>

              <section aria-labelledby="graph-edges-heading">
                <h2 id="graph-edges-heading" className="mb-2 text-sm font-semibold">Edges</h2>
                <table className="w-full text-left text-sm">
                  <caption className="sr-only">Credential graph edges</caption>
                  <thead>
                    <tr className="border-b border-border text-muted-foreground">
                      <th scope="col" className="py-2 pr-4 font-medium">From</th>
                      <th scope="col" className="py-2 pr-4 font-medium">Type</th>
                      <th scope="col" className="py-2 pr-4 font-medium">To</th>
                      <th scope="col" className="py-2 font-medium">Explanation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.edges.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-4 text-muted-foreground">No graph edges returned.</td>
                      </tr>
                    )}
                    {data.edges.map((edge) => (
                      <tr key={`${edge.from}-${edge.type}-${edge.to}`} className="border-b border-border">
                        <td className="py-2 pr-4">{nodeByID.get(edge.from)?.name ?? edge.from}</td>
                        <td className="py-2 pr-4 font-mono text-xs">{edge.type}</td>
                        <td className="py-2 pr-4">{nodeByID.get(edge.to)?.name ?? edge.to}</td>
                        <td className="py-2 text-muted-foreground">{edgeExplanation(edge.type)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            </div>

            <NodeDetail node={selectedNode} />
          </div>

          {impact && <ImpactPanel impact={impact} />}
          {reachable && <ReachablePanel reachable={reachable} />}

          <section aria-labelledby="graph-query-heading" className="mt-6 rounded-md border border-border p-4">
            <h2 id="graph-query-heading" className="text-sm font-semibold">
              Graph query
            </h2>
            <form
              className="mt-3 grid gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                void runGraphQuery();
              }}
            >
              <label className="grid gap-1 text-sm font-medium" htmlFor="graph-query">
                Cypher-style query
                <textarea
                  id="graph-query"
                  value={queryText}
                  onChange={(e) => setQueryText(e.target.value)}
                  className="min-h-24 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                />
              </label>
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={busy === "query" || !queryText.trim()}>
                  Run graph query
                </Button>
                {queryResult && (
                  <a
                    className="inline-flex items-center rounded-md border border-border px-3 py-2 text-sm underline"
                    download="graph-query-results.json"
                    href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(queryResult.rows, null, 2))}`}
                  >
                    Export query rows
                  </a>
                )}
              </div>
            </form>
            {queryError && (
              <div className="mt-3">
                <ErrorState title="Graph query unavailable">{queryError}</ErrorState>
              </div>
            )}
            {queryResult && (
              <pre className="mt-3 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">
                {JSON.stringify(queryResult.rows, null, 2)}
              </pre>
            )}
          </section>
        </>
      )}
    </section>
  );
}

function NodeDetail({ node }: { node: GraphNode | null }) {
  if (!node) {
    return (
      <aside className="rounded-md border border-border p-4 text-sm text-muted-foreground">
        Select a graph node to inspect its attributes and drilldown links.
      </aside>
    );
  }
  const attrRows = Object.entries(node.attrs ?? {});
  return (
    <aside aria-labelledby="graph-node-detail-heading" className="rounded-md border border-border p-4 text-sm">
      <h2 id="graph-node-detail-heading" className="text-lg font-semibold">Node detail</h2>
      <dl className="mt-3 grid gap-2">
        <div>
          <dt className="font-medium text-muted-foreground">Name</dt>
          <dd>{node.name || "-"}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Kind</dt>
          <dd>{node.kind}</dd>
        </div>
        <div>
          <dt className="font-medium text-muted-foreground">Opaque node ID</dt>
          <dd className="break-all font-mono text-xs">{node.id}</dd>
        </div>
      </dl>
      <h3 className="mt-4 font-semibold">Attributes</h3>
      {attrRows.length > 0 ? (
        <dl className="mt-2 grid gap-2">
          {attrRows.map(([key, value]) => (
            <div key={key}>
              <dt className="font-medium text-muted-foreground">{key}</dt>
              <dd className="break-all font-mono text-xs">{displayValue(value)}</dd>
            </div>
          ))}
        </dl>
      ) : (
        <p className="mt-1 text-muted-foreground">No attributes returned for this node.</p>
      )}
      <h3 className="mt-4 font-semibold">Drilldown links</h3>
      <ul className="mt-2 space-y-1">
        {node.id.startsWith("cert:") && (
          <li>
            <a className="text-primary underline" href={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
              Certificate detail
            </a>
          </li>
        )}
        <li>
          <a className="text-primary underline" href={`/risk?node=${encodeURIComponent(node.id)}`}>Risk row</a>
        </li>
        <li>
          <a className="text-primary underline" href={`/identities?node=${encodeURIComponent(node.id)}`}>Lifecycle identity</a>
        </li>
        <li>
          <a className="text-primary underline" href={`/audit?node=${encodeURIComponent(node.id)}`}>Audit evidence</a>
        </li>
      </ul>
    </aside>
  );
}

function ImpactPanel({ impact }: { impact: GraphImpact }) {
  return (
    <section aria-labelledby="blast-radius-heading" className="mt-6 rounded-md border border-border p-4">
      <h2 id="blast-radius-heading" className="text-sm font-semibold">
        Blast-radius paths and by-kind summary
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        Compromising {impact.node.name || impact.node.id} affects {impact.affected.length} node{impact.affected.length === 1 ? "" : "s"}.
      </p>
      <dl className="mt-3 grid gap-2 sm:grid-cols-3">
        {Object.entries(impact.by_kind ?? {}).map(([kind, value]) => (
          <div key={kind} className="rounded-md border border-border p-2">
            <dt className="font-medium">{kind}</dt>
            <dd>{displayValue(value)}</dd>
          </div>
        ))}
      </dl>
      <AffectedNodes nodes={impact.affected} />
    </section>
  );
}

function ReachablePanel({ reachable }: { reachable: GraphReachable }) {
  return (
    <section aria-labelledby="reachable-heading" className="mt-6 rounded-md border border-border p-4">
      <h2 id="reachable-heading" className="text-sm font-semibold">
        Reachable nodes
      </h2>
      <p className="mt-1 text-sm text-muted-foreground">
        {reachable.nodes.length} node{reachable.nodes.length === 1 ? "" : "s"} reachable from {reachable.from}.
      </p>
      <AffectedNodes nodes={reachable.nodes} />
    </section>
  );
}

function AffectedNodes({ nodes }: { nodes: GraphNode[] }) {
  return (
    <ul className="mt-3 grid gap-2 md:grid-cols-2">
      {nodes.map((node) => (
        <li key={node.id} className="rounded-md border border-border p-2">
          <p className="font-medium">{node.name || node.id}</p>
          <p className="font-mono text-xs text-muted-foreground">{node.kind} · {node.id}</p>
          <div className="mt-1 flex flex-wrap gap-2 text-xs">
            <a className="text-primary underline" href={`/risk?node=${encodeURIComponent(node.id)}`}>Risk</a>
            <a className="text-primary underline" href={`/audit?node=${encodeURIComponent(node.id)}`}>Audit</a>
            {node.id.startsWith("cert:") && (
              <a className="text-primary underline" href={`/certificates?credential=${encodeURIComponent(node.id.slice(5))}`}>
                Certificate
              </a>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

function displayValue(value: unknown): string {
  if (value == null) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function edgeExplanation(type: string): string {
  switch (type) {
    case "ISSUED":
      return "The source issued or signed the target credential.";
    case "OWNS":
      return "The source owner controls or is accountable for the target.";
    case "DEPLOYED_TO":
      return "The credential is deployed to that workload or resource.";
    case "GRANTS_ACCESS":
      return "The source grants access to the target resource.";
    case "CONNECTS_TO":
      return "The source can connect to the target.";
    case "EXHIBITS":
      return "The source exhibits the target crypto asset or finding.";
    default:
      return "Served graph relationship from the backend.";
  }
}

function noticeFor(err: unknown, fallback: string): Notice {
  if (err instanceof ApiError && err.status === 403) {
    return { kind: "permission", message: "Your session cannot read the credential graph for this tenant." };
  }
  return { kind: "error", message: apiProblemMessage(err, fallback) };
}

function apiProblemMessage(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.retryAfterSeconds != null) return `${fallback}: retry in ${err.retryAfterSeconds}s.`;
    const body = err.body.trim();
    if (body) {
      try {
        const problem = JSON.parse(body) as { detail?: string; title?: string };
        const message = problem.detail || problem.title;
        if (message) return `${fallback}: ${message}`;
      } catch {
        return `${fallback}: ${body}`;
      }
    }
    return `${fallback}: ${err.message}`;
  }
  return `${fallback}: ${err instanceof Error ? err.message : String(err)}`;
}
