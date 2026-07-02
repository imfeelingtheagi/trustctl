# Product decision register

This page is the REPORT-007 control. It is a parking place for decisions that an
audit agent can recommend but must not make. Every row below is **not product truth until approved**
by a human product owner. Until then, public docs, web UI, pricing copy, and
sales claims must treat each row as a recommendation.

Status vocabulary:

- **Needs human decision** means the recommended path is written down, but the
  product has not adopted it.
- **Approved** means a human owner has accepted the decision and assigned the
  implementation work.
- **Implemented** means the accepted decision is wired into docs, UI, license
  surfaces, and tests.

## Narrative decisions

| ID | Status | Recommended decision | Where it should land after approval |
|----|--------|----------------------|-------------------------------------|
| NARRATIVE-001 | Needs human decision | Adopt "self-hosted non-human identity management / Machine IAM control plane" as the front-door category label. | README first viewport, docs index, dashboard overview, quickstart copy, and the category leadership ledger. |
| NARRATIVE-002 | Needs human decision | Use no per-certificate and no ephemeral-identity billing as the recommended cost posture; keep certificate and identity counts as operational telemetry or capacity signals. | Pricing page, editions page, Provider billing docs, and any challenger-cost narrative. |
| NARRATIVE-003 | Needs human decision | Publish an evidence-bound proof rail that uses live eval receipts, served NHI route coverage, OWASP NHI mapping, and current limitations. Do not imply analyst placement without a dated external citation. | README proof block, docs index proof rail, security/compliance overview, and release notes. |
| NARRATIVE-004 | Needs human decision | Split the unified-scope story into served-now, conditional, partial, and roadmap rows tied to served_state evidence. | Feature catalog, category leadership ledger, docs index summary, and web console overview. |

## Packaging decisions

| ID | Status | Recommended decision | Where it should land after approval |
|----|--------|----------------------|-------------------------------------|
| PACKAGING-001 | Needs human decision | Publish a public pricing posture that states the billable unit, what Community includes, what needs Enterprise/Provider/Managed, and what is never billable. | Pricing page, editions page, Provider docs, and procurement FAQ. |
| PACKAGING-002 | Needs human decision | Expand the editions page into a buyer-facing matrix with Community, Enterprise, Provider, and Managed columns, mapped across the P-01..P-09 capability line plus managed offering P-15. | `docs/editions.md`, web Platform packaging panel, and license feature table appendix. |
| PACKAGING-003 | Needs human decision | Publish the Provider billing unit explicitly; keep certificate counters as operational telemetry and avoid making issued or stored certificates the primary billable axis. | Provider billing docs, usage export docs, and any no-per-certificate cost claim. |
| PACKAGING-004 | Needs human decision | Choose and publish the managed-offering boundary: first-party SaaS, MSP/Provider, or self-hosted Provider, including support, data-residency, and operating-responsibility terms. | Managed offering page, Provider docs, support runbooks, and sales packaging. |

## Guardrail

These rows can guide implementation, but they cannot be counted as served
Category-Leadership proof, pricing truth, or positioning truth while their status
is **Needs human decision**. A future change that moves a row to Approved or
Implemented must also add the exact owner/date, update the linked product
surfaces, and add or update tests that prevent stale copy.
