import test from "node:test";
import assert from "node:assert/strict";
import { normalizeVendorSelection, SUPPORTED_VENDORS } from "./vendorCatalog.ts";

test("drops removed and unknown vendors from persisted selections", () => {
  assert.equal(SUPPORTED_VENDORS.includes("Criminal IP" as never), false);
  assert.deepEqual(
    normalizeVendorSelection(["VirusTotal", "Criminal IP", "Censys", "Team Cymru", "Hybrid Analysis", "MetaDefender", "CIRCL hashlookup", "Pulsedive", "Unknown Vendor"]),
    ["VirusTotal"],
  );
});
