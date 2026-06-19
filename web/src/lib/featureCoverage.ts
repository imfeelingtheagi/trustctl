import featureMapBacklog from "@/lib/feature-map-backlog.json";

export type FeatureCoverageState = "operate" | "observe" | "disclose";
export type FeatureCoveragePhase = "P0" | "P1" | "P2" | "P3";

export interface FeatureMapBacklogItem {
  id: string;
  feature_id: string;
  feature: string;
  domain: string;
  phase: FeatureCoveragePhase;
  priority: number;
  backend_status: string;
  current_frontend_mapping: string;
  target_gui_mapping: string;
  acceptance_test: string;
  source_backend: string[];
  source_frontend: string[];
  status: string;
  notes: string;
}

interface FeatureMapBacklog {
  items: FeatureMapBacklogItem[];
}

export interface FeatureCoverageItem {
  id: string;
  backlogId: string;
  name: string;
  domain: string;
  phase: FeatureCoveragePhase;
  priority: number;
  state: FeatureCoverageState;
  backendStatus: string;
  currentMapping: string;
  targetMapping: string;
  acceptanceTest: string;
  sourceBackend: string[];
  sourceFrontend: string[];
}

export interface FeatureCoverageDomain {
  name: string;
  count: number;
  operate: number;
  observe: number;
  disclose: number;
  phases: FeatureCoveragePhase[];
}

const backlog = featureMapBacklog as FeatureMapBacklog;

export function coverageStateFor(item: FeatureMapBacklogItem): FeatureCoverageState {
  if (item.current_frontend_mapping === "none" || /roadmap-disclosure/i.test(item.current_frontend_mapping)) {
    return "disclose";
  }
  if (/issue|create|approve|actions|Wizard|Profiles|Assistant|MCP|Login/i.test(item.current_frontend_mapping)) {
    return "operate";
  }
  return "observe";
}

export const featureCoverageItems: FeatureCoverageItem[] = backlog.items
  .map((item) => ({
    id: item.feature_id,
    backlogId: item.id,
    name: item.feature,
    domain: item.domain,
    phase: item.phase,
    priority: item.priority,
    state: coverageStateFor(item),
    backendStatus: item.backend_status,
    currentMapping: item.current_frontend_mapping,
    targetMapping: item.target_gui_mapping,
    acceptanceTest: item.acceptance_test,
    sourceBackend: item.source_backend,
    sourceFrontend: item.source_frontend,
  }))
  .sort((a, b) => a.priority - b.priority);

export const featureCoverageDomains: FeatureCoverageDomain[] = Object.values(
  featureCoverageItems.reduce<Record<string, FeatureCoverageDomain>>((domains, item) => {
    const domain =
      domains[item.domain] ??
      (domains[item.domain] = {
        name: item.domain,
        count: 0,
        operate: 0,
        observe: 0,
        disclose: 0,
        phases: [],
      });
    domain.count += 1;
    domain[item.state] += 1;
    if (!domain.phases.includes(item.phase)) domain.phases.push(item.phase);
    return domains;
  }, {}),
).sort((a, b) => a.name.localeCompare(b.name));

export const featureCoverageTotals = {
  features: featureCoverageItems.length,
  domains: featureCoverageDomains.length,
  operate: featureCoverageItems.filter((item) => item.state === "operate").length,
  observe: featureCoverageItems.filter((item) => item.state === "observe").length,
  disclose: featureCoverageItems.filter((item) => item.state === "disclose").length,
  phases: {
    P0: featureCoverageItems.filter((item) => item.phase === "P0").length,
    P1: featureCoverageItems.filter((item) => item.phase === "P1").length,
    P2: featureCoverageItems.filter((item) => item.phase === "P2").length,
    P3: featureCoverageItems.filter((item) => item.phase === "P3").length,
  },
} as const;
