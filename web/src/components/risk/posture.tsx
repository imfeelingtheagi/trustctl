import { DashboardGrid } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import type { CredentialRisk } from "@/lib/api";

/** RiskPosture is a non-duplicating summary of the credential-risk read model.
 * It never renders individual subjects (the Risk page's grid owns those rows);
 * it only reports counts and bands so it can sit above that grid without
 * fighting it in tests or confusing the operator with the same name twice. */
export function RiskPosture({ risks }: { risks: CredentialRisk[] }) {
  const critical = risks.filter((risk) => risk.score >= 90).length;
  const high = risks.filter((risk) => risk.score >= 70 && risk.score < 90).length;
  const orphaned = risks.filter((risk) => !risk.owner_active).length;
  const avg = risks.length ? Math.round(risks.reduce((sum, risk) => sum + risk.score, 0) / risks.length) : 0;
  return (
    <DashboardGrid>
      <StatTile label="Credentials scored" value={risks.length} />
      <StatTile label="Critical (90+)" value={critical} tone={critical ? "critical" : undefined} />
      <StatTile label="High (70-89)" value={high} tone={high ? "high" : undefined} />
      <StatTile label="Orphaned" value={orphaned} tone={orphaned ? "warning" : undefined} />
      <StatTile label="Average score" value={avg} />
    </DashboardGrid>
  );
}
