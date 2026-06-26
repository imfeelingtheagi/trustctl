import { DashboardGrid, SectionCard, AttentionList, AttentionRow } from "@/components/dashboard";
import { StatTile } from "@/components/charts";
import { StatusBadge } from "@/components/StatusBadge";
import type { Issuer, Profile } from "@/lib/api";

export function CAOverview({ issuers, profiles }: { issuers: Issuer[]; profiles: Profile[] }) {
  const internal = issuers.filter((issuer) => issuer.internal).length;
  const external = issuers.length - internal;
  return (
    <div className="grid gap-4">
      <DashboardGrid>
        <StatTile label="Issuing CAs" value={issuers.length} />
        <StatTile label="Internal" value={internal} />
        <StatTile label="External" value={external} />
        <StatTile label="Issuance profiles" value={profiles.length} />
      </DashboardGrid>
      <SectionCard title="Issuance profiles" description="versioned issuance policy bound to issuance">
        {profiles.length === 0 ? (
          <p className="text-caption text-muted-foreground">No profiles defined.</p>
        ) : (
          <AttentionList ariaLabel="Issuance profiles">
            {profiles.map((profile) => (
              <AttentionRow key={profile.id}>
                <span className="flex-1 truncate font-medium">{profile.name}</span>
                <span className="text-caption tabular-nums text-muted-foreground">v{profile.version}</span>
                <StatusBadge
                  value={profile.active === false ? "inactive" : "active"}
                  label={profile.active === false ? "inactive" : "active"}
                  tone={profile.active === false ? "neutral" : "success"}
                />
              </AttentionRow>
            ))}
          </AttentionList>
        )}
      </SectionCard>
    </div>
  );
}
