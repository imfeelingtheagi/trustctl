import { useState } from "react";
import { SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { api, type GraphNode, type GraphImpact } from "@/lib/api";

export function BlastRadiusExplorer({ nodes }: { nodes: GraphNode[] }) {
  const [impact, setImpact] = useState<GraphImpact | null>(null);
  const [selected, setSelected] = useState<string>("");
  const [error, setError] = useState<string | null>(null);

  async function explore(id: string) {
    setSelected(id);
    setError(null);
    setImpact(null);
    if (!id) return;
    try {
      setImpact(await api.graphBlastRadius(id));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <SectionCard title="Blast radius explorer" description="pick a credential and see everything that breaks if it is compromised">
      <label className="grid gap-1 text-body">
        <span className="font-medium">Credential</span>
        <select value={selected} onChange={(event) => void explore(event.target.value)} className="min-h-9 rounded-control border border-border bg-background px-2 text-body">
          <option value="">Select a node…</option>
          {nodes.map((node) => (
            <option key={node.id} value={node.id}>
              {node.name} ({node.kind})
            </option>
          ))}
        </select>
      </label>
      {impact ? (
        <div className="mt-3">
          <p className="text-caption text-muted-foreground">{impact.affected.length} affected credentials</p>
          <AttentionList ariaLabel="Affected credentials">
            {impact.affected.map((node) => (
              <AttentionRow key={node.id}>
                <span className="flex-1 truncate">{node.name}</span>
                <span className="w-28 truncate text-caption text-muted-foreground">{node.kind}</span>
              </AttentionRow>
            ))}
          </AttentionList>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="mt-2 text-caption text-risk-critical">
          {error}
        </p>
      ) : null}
    </SectionCard>
  );
}
