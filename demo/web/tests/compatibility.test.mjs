import assert from "node:assert/strict";
import { compatibilityReport, compatibilityText } from "../compatibility.mjs";

const checksum = "a".repeat(64);
const commit = "b".repeat(40);
const build = { target: "windows", releaseTag: "v0.1.1", librarySha256: checksum, converterCommit: commit };
const catalog = {
  schema: 1, platform: "windows", archive_sha256: checksum,
  libraries: ["libSceA.prx", "libSceB.prx", "libc.prx"],
  exports: { AAAAAAAAAAA: ["libSceA.prx"], BBBBBBBBBBB: ["libSceB.prx"], CCCCCCCCCCC: ["libc.prx"], DDDDDDDDDDD: ["libSceA.prx", "libSceB.prx"] },
  source_stubs: [{ library: "libSceA.prx", nid: "AAAAAAAAAAA", name: "sceExampleThrow" }, { library: "libSceA.prx", nid: "DDDDDDDDDDD", name: "sceExampleLiveElsewhere" }],
  source_commit: commit, source_dirty: false, library_commit: null, source_warnings: []
};
const entry = (nid, library = "libSceA.prx", input = "main.elf") => ({ nid, library, input });
const audit = {
  imports: [entry("AAAAAAAAAAA#qualified"), entry("AAAAAAAAAAA"), entry("BBBBBBBBBBB"), entry("CCCCCCCCCCC"), entry("DDDDDDDDDDD"), entry("EEEEEEEEEEE", "missing.prx"), entry("FFFFFFFFFFF", "Guest.prx"), entry("GGGGGGGGGGG", "")],
  modules: [{ path: "app0/sce_module/guest.guest.prx", names: ["Guest.prx", ""] }],
  needed: ["libSceA.prx", "missing-no-import.prx", "$ORIGIN/app0/sce_module/guest.guest.prx"]
};
const report = compatibilityReport(audit, catalog, build);
assert.deepEqual(report.counts, { references: 8, unique_imports: 7, exported: 3, absent: 2, other_provider: 1, guest: 1, source_stubs: 2 });
assert.equal(report.imports.reduce((sum, record) => sum + record.references, 0), 8);
assert.deepEqual(report.missing_libraries, ["missing-no-import.prx", "missing.prx"]);
assert.equal(report.imports.find(record => record.nid === "AAAAAAAAAAA").references, 2);
assert.equal(report.imports.find(record => record.nid === "DDDDDDDDDDD").source_stub, true);
assert.equal(report.imports.find(record => record.nid === "GGGGGGGGGGG").kind, "absent");
assert.equal(report.build_match, "unknown");
assert.equal(report.library_commit, null);
const text = compatibilityText(report);
assert.match(text, /missing-no-import.prx/u);
assert.match(text, /sceExampleThrow/u);
assert.match(text, /weak imports may be optional/u);
assert.match(text, /packaged behavior unverified/u);
assert.match(text, /guest module imports are not fully audited/u);
assert.match(text, /Library build commit: unknown/u);
assert.match(text, /BBBBBBBBBBB.*libSceB.prx/u);

const qualified = compatibilityReport({ imports: [entry("AAAAAAAAAAA", "LIBSCEA.PRX"), entry("FFFFFFFFFFF", "GUEST.PRX")], modules: audit.modules, needed: ["LIBSCEA.PRX"] }, catalog, build);
assert.equal(qualified.counts.exported, 1);
assert.equal(qualified.counts.guest, 1);
assert.deepEqual(qualified.missing_libraries, []);
const linux = compatibilityReport({ imports: [entry("FFFFFFFFFFF", "GUEST.PRX")], modules: audit.modules, needed: [] }, { ...catalog, platform: "linux" }, { ...build, target: "linux" });
assert.equal(linux.counts.absent, 1);
assert.deepEqual(linux.missing_libraries, ["GUEST.PRX"]);
const mixedLinux = compatibilityReport({ imports: [entry("DDDDDDDDDDD")], modules: [], needed: [] }, { ...catalog, platform: "linux" }, { ...build, target: "linux" });
assert.equal(mixedLinux.counts.source_stubs, 0);
const alias = compatibilityReport({ imports: [{ ...entry("EEEEEEEEEEE", "libGuest.suprx"), guest: true }], modules: [{ path: "app0/sce_module/renamed.prx.guest.prx", names: ["renamed.prx", ""] }], needed: ["$ORIGIN/app0/sce_module/renamed.prx.guest.prx"] }, { ...catalog, platform: "linux" }, { ...build, target: "linux" });
assert.equal(alias.counts.guest, 1);
assert.equal(alias.counts.absent, 0);
assert.deepEqual(alias.missing_libraries, []);

const moduleImports = compatibilityReport({ ...audit, imports: [entry("AAAAAAAAAAA"), entry("AAAAAAAAAAA", "libSceA.prx", "sce_module/module.prx")] }, catalog, build);
assert.equal(moduleImports.counts.unique_imports, 2);
assert.equal(moduleImports.counts.source_stubs, 2);
const matching = compatibilityReport(audit, { ...catalog, library_commit: commit }, build);
assert.equal(matching.build_match, "matching");
const mismatched = compatibilityReport(audit, { ...catalog, source_commit: "c".repeat(40), library_commit: "d".repeat(40), source_dirty: true }, build);
assert.equal(mismatched.build_match, "different");
assert.equal(mismatched.warnings.length, 3);
const unknown = compatibilityReport({ imports: [], modules: [], needed: [] }, { ...catalog, source_commit: null, source_dirty: null, source_warnings: ["Throwing stub analysis is unavailable."] }, { ...build, converterCommit: null });
assert.equal(unknown.build_match, "unknown");
assert.match(compatibilityText(unknown), /unavailable/u);

for (const changed of [{ schema: 2 }, { platform: "linux" }, { archive_sha256: "e".repeat(64) }]) assert.throws(() => compatibilityReport(audit, { ...catalog, ...changed }, build), /does not match/u);
assert.throws(() => compatibilityReport(null, catalog, build), /did not provide import information/u);
assert.throws(() => compatibilityReport({ ...audit, imports: [entry(null)] }, catalog, build), /Invalid converter import/u);
const unusual = compatibilityReport({ imports: [entry("__proto__"), entry("constructor"), entry("<script>", "library<name>.prx", "title<script>.elf")], modules: [], needed: [] }, catalog, build);
assert.equal(unusual.counts.absent, 3);
assert.match(compatibilityText(unusual), /title<script>.elf/u);
assert.deepEqual(catalog.source_stubs[0], { library: "libSceA.prx", nid: "AAAAAAAAAAA", name: "sceExampleThrow" });
console.log("Compatibility report: import accounting, provider rules, guest scope, provenance and source warnings verified");
