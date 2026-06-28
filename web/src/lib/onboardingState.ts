// Benign first-run UI state: a single boolean — "has the operator finished
// onboarding on this browser" — persisted to localStorage so the empty-state
// wizard latches closed instead of re-prompting every visit (audit U2). This is
// never auth material: it carries no token, tenant, principal, or secret.
//
// It lives in its own module so the SURFACE-I01 storage guard
// (src/__tests__/security_sinks.test.ts) can allow exactly this benign key the
// same way it allows the theme preference and DataGrid view metadata — keeping
// raw localStorage out of page/component code.
const ONBOARDING_COMPLETE_KEY = "trstctl:onboarding-complete";

/** True once the first-run wizard has been completed on this browser. */
export function isOnboardingComplete(): boolean {
  try {
    return localStorage.getItem(ONBOARDING_COMPLETE_KEY) === "1";
  } catch {
    return false;
  }
}

/** Latch onboarding as finished so the dashboard stops showing the setup empty-state. */
export function markOnboardingComplete(): void {
  try {
    localStorage.setItem(ONBOARDING_COMPLETE_KEY, "1");
  } catch {
    /* storage unavailable — onboarding just won't latch across reloads, which is safe */
  }
}

/** Clear the latch so the wizard re-prompts on next visit (used by "start over"). */
export function resetOnboarding(): void {
  try {
    localStorage.removeItem(ONBOARDING_COMPLETE_KEY);
  } catch {
    /* storage unavailable — nothing to reset */
  }
}
