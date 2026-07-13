import test from "node:test";
import assert from "node:assert/strict";
import { filterNewsletterAdvisories, formatNewsletterDate } from "./newsletterView.ts";

test("formats today's full date in the selected language", () => {
  const date = new Date("2026-07-13T12:00:00-03:00");

  assert.equal(formatNewsletterDate(date, "pt"), "Hoje, 13 de julho de 2026");
  assert.equal(formatNewsletterDate(date, "en"), "Today, July 13, 2026");
});

test("keeps matching advisories from different months", () => {
  const advisories = [
    { title: "July item", description: "alpha", source: "CISA", pubDate: "2026-07-01", layer: 1, severity: "High" },
    { title: "June item", description: "alpha", source: "Vendor", pubDate: "2026-06-01", layer: 2, severity: "Medium" },
  ];

  const result = filterNewsletterAdvisories(advisories, {
    search: "alpha",
    layer: "all",
    severity: "all",
    kevOnly: false,
    sortByRelevance: false,
  });

  assert.deepEqual(result.map((item) => item.title), ["July item", "June item"]);
});
