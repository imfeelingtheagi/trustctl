import { SectionCard, DashboardGrid, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { RiskScore, useRisk } from "@/components/risk";
import type { Identity, CredentialRisk, Owner } from "@/lib/api";

function humanize(value: string): string {
  const text = value.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function kindCounts(identities: Identity[]): Array<[string, number]> {
  const map = new Map<string, number>();
  for (const identity of identities) map.set(identity.kind, (map.get(identity.kind) ?? 0) + 1);
  return [...map.entries()].sort((a, b) => b[1] - a[1]);
}

export function NhiInventory({ identities, risks = [] }: { identities: Identity[]; risks?: CredentialRisk[] }) {
  const kinds = kindCounts(identities);
  const highRisk = risks.filter((risk) => risk.score >= 70).length;
  return (
    <SectionCard title="Non-human identity inventory" description="every machine identity by type, with a shared risk lens">
      <DashboardGrid>
        <StatTile label="Total identities" value={identities.length} />
        {kinds.map(([kind, count]) => (
          <StatTile key={kind} label={humanize(kind)} value={count} />
        ))}
        <StatTile label="High risk" value={highRisk} tone={highRisk ? "high" : undefined} />
      </DashboardGrid>
    </SectionCard>
  );
}

export function OrphanGovernance({ owners = [] }: { owners?: Owner[] }) {
  const { data: risks } = useRisk();
  const orphans = risks.filter((risk) => !risk.owner_active);
  const coverage = risks.length ? Math.round(((risks.length - orphans.length) / risks.length) * 100) : 100;
  return (
    <div className="grid gap-4">
      <DashboardGrid>
        <StatTile label="Credentials" value={risks.length} />
        <StatTile label="Registered owners" value={owners.length} />
        <StatTile label="Orphaned" value={orphans.length} tone={orphans.length ? "high" : undefined} />
        <StatTile label="Ownership coverage" value={`${coverage}%`} />
      </DashboardGrid>
      <SectionCard title="Orphaned credentials" description="machine identities whose human custodian is gone or inactive">
        {orphans.length === 0 ? (
          <p className="text-caption text-muted-foreground">Every credential has an active owner.</p>
        ) : (
          <AttentionList ariaLabel="Orphaned credentials">
            {orphans.map((risk) => (
              <AttentionRow key={risk.credential_id}>
                <span className="flex-1 truncate font-mono text-caption">{risk.subject}</span>
                <span className="w-24 truncate text-caption text-muted-foreground">{risk.kind}</span>
                <RiskScore score={risk.score} />
              </AttentionRow>
            ))}
          </AttentionList>
        )}
      </SectionCard>
    </div>
  );
}
