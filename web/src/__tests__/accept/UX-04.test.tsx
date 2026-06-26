import { describe, expect, it } from "vitest";
import { extractedMessages } from "@/i18n/extractedMessages.gen";
import { messages } from "@/i18n/messages";

const internalVocabulary = [
  { label: "served/not-served implementation status", pattern: /\bserved\b/i },
  { label: "library-only implementation tier", pattern: /\blibrary[- ]only\b/i },
  { label: "feature ID", pattern: /\bF-\d+\b|\bF\d+\b/ },
  { label: "architecture invariant ID", pattern: /\bAN-\d+\b/ },
  { label: "internal Go package path", pattern: /\binternal\/[A-Za-z0-9_./-]+/ },
  { label: "TRSTCTL environment variable", pattern: /\bTRSTCTL_[A-Z0-9_]+\b/ },
  { label: "literal REST path", pattern: /\/api\/v\d+\//i },
  { label: "literal HTTP route", pattern: /\b(?:GET|POST|PUT|PATCH|DELETE)\s+\/[A-Za-z0-9_.{}|/-]+/i },
];

const catalogEntries = [
  ...extractedMessages.map((entry) => ({
    key: entry.key,
    message: entry.defaultMessage,
    sources: [...entry.sources],
  })),
  ...Object.entries(messages).map(([key, entry]) => ({
    key,
    message: entry.defaultMessage,
    sources: [`messages.${key}`],
  })),
];

describe("UX-04 customer copy vocabulary", () => {
  it("keeps internal implementation terms out of rendered copy", () => {
    const offenders: string[] = [];
    for (const entry of catalogEntries) {
      for (const rule of internalVocabulary) {
        if (!rule.pattern.test(entry.message)) continue;
        offenders.push(`${entry.sources.join(", ")}: ${rule.label}: ${entry.message}`);
      }
    }

    expect(offenders, `internal customer-copy leak(s):\n${offenders.join("\n")}`).toEqual([]);
  });
});
