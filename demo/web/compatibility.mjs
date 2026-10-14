const coverage = [
  "Checks the executable registry, reported guest module imports and final executable dependencies. Other guest module imports are not fully audited.",
  "Import strength is not recorded; a missing weak import can be optional. Functions loaded later are not checked.",
  "Exports do not verify behavior. Source warnings describe throwing stubs in the converter source, not verified behavior of the packaged libraries.",
  "This report does not run the app or verify graphics, hardware requirements or game compatibility."
];

export function compatibilityReport(audit, catalog, build) {
  if (!audit || !Array.isArray(audit.imports) || !Array.isArray(audit.modules) || !Array.isArray(audit.needed)) throw new Error("The converter did not provide import information. Reload this page.");
  if (catalog.schema !== 1 || catalog.platform !== build.target || catalog.archive_sha256 !== build.librarySha256) throw new Error("The compatibility catalog does not match the selected system libraries. Reload this page.");
  if (!Array.isArray(catalog.libraries) || !catalog.exports || !Array.isArray(catalog.source_stubs)) throw new Error("Invalid compatibility catalog");
  const normalize = name => build.target === "windows" ? name.toLowerCase() : name;
  const libraries = new Set(catalog.libraries.map(normalize));
  const modules = new Set(audit.modules.flatMap(module => [...module.names, "$ORIGIN/" + module.path, module.path]).filter(Boolean).map(normalize));
  const stubs = new Map(catalog.source_stubs.map(record => [JSON.stringify([normalize(record.library), record.nid]), record.name]));
  const records = new Map();
  for (const entry of audit.imports) {
    if (typeof entry.nid !== "string" || typeof entry.library !== "string" || typeof entry.input !== "string") throw new Error("Invalid converter import information");
    const nid = entry.nid.split("#", 1)[0];
    const key = JSON.stringify([entry.input, nid, entry.library]);
    if (records.has(key)) { ++records.get(key).references; continue; }
    const providers = Object.hasOwn(catalog.exports, nid) ? catalog.exports[nid] : [];
    const guest = entry.guest === true || modules.has(normalize(entry.library));
    const mismatch = !guest && providers.length > 0 && Boolean(entry.library) && !providers.some(provider => normalize(provider) === normalize(entry.library) || normalize(provider) === "libc.prx");
    const kind = guest ? "guest" : !providers.length ? "absent" : mismatch ? "other_provider" : "exported";
    const named = providers.filter(provider => normalize(provider) === normalize(entry.library));
    const effective = build.target === "windows" && entry.library ? named.length ? named : providers.filter(provider => normalize(provider) === "libc.prx") : providers;
    const sourceNames = effective.map(provider => stubs.get(JSON.stringify([normalize(provider), nid])));
    const sourceStub = !guest && effective.length > 0 && sourceNames.every(Boolean);
    records.set(key, { input: entry.input, nid, library: entry.library, references: 1, kind, providers, source_stub: sourceStub, name: sourceStub ? sourceNames[0] : null });
  }
  const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const imports = [...records.values()].sort((a, b) => compare(a.input, b.input) || compare(a.library, b.library) || compare(a.nid, b.nid));
  const missing = new Set(audit.needed.filter(name => !libraries.has(normalize(name)) && !modules.has(normalize(name))));
  for (const record of imports) if (record.kind !== "guest" && record.library && !libraries.has(normalize(record.library)) && !modules.has(normalize(record.library))) missing.add(record.library);
  const counts = { references: audit.imports.length, unique_imports: imports.length };
  for (const kind of ["exported", "absent", "other_provider", "guest"]) counts[kind] = imports.filter(record => record.kind === kind).length;
  counts.source_stubs = imports.filter(record => record.source_stub).length;
  const converterCommit = build.converterCommit ?? null;
  const libraryCommit = catalog.library_commit ?? null;
  const matching = converterCommit && libraryCommit ? converterCommit === libraryCommit ? "matching" : "different" : "unknown";
  const warnings = [...(catalog.source_warnings ?? [])];
  if (matching === "different") warnings.push("Converter and system libraries identify different build commits.");
  if (catalog.source_commit && converterCommit && catalog.source_commit !== converterCommit) warnings.push("Source warnings come from a different commit than the converter.");
  if (catalog.source_dirty && !warnings.includes("The source checkout contains uncommitted changes.")) warnings.push("The source checkout contains uncommitted changes.");
  if (build.converterDirty) warnings.push("The converter was built with uncommitted source changes.");
  return {
    schema: 1, target: build.target, release: build.releaseTag, archive_sha256: build.librarySha256,
    converter_commit: converterCommit, converter_dirty: build.converterDirty ?? null, library_commit: libraryCommit, build_match: matching,
    source_commit: catalog.source_commit ?? null, source_dirty: catalog.source_dirty ?? null,
    counts, missing_libraries: [...missing].sort(), imports, warnings, coverage
  };
}

export function compatibilityText(report) {
  const lines = [
    `Target: ${report.target} · Libraries: ${report.release}`,
    `Converter source commit: ${report.converter_commit ?? "unknown"} · Uncommitted changes: ${report.converter_dirty ?? "unknown"}`,
    `Library build commit: ${report.library_commit ?? "unknown"} · Build match: ${report.build_match}`,
    `Source warnings commit: ${report.source_commit ?? "unknown"} · Uncommitted changes: ${report.source_dirty ?? "unknown"}`,
    "", `${report.counts.references} references, ${report.counts.unique_imports} unique reported imports`,
    `${report.counts.exported} exported, ${report.counts.absent} absent, ${report.counts.other_provider} other provider, ${report.counts.guest} guest module`
  ];
  for (const [title, records] of [
    ["Needed libraries with no packaged file", report.missing_libraries],
    ["Missing exports (weak imports may be optional)", report.imports.filter(record => record.kind === "absent")],
    ["Exports found only in another library (can fail on Windows)", report.imports.filter(record => record.kind === "other_provider")],
    ["Source throwing stubs (packaged behavior unverified)", report.imports.filter(record => record.source_stub)]
  ]) {
    if (!records.length) continue;
    lines.push("", `${title} (${records.length})`);
    for (const record of records) lines.push(typeof record === "string" ? `  ${record}` : `  ${record.input}: ${record.library || "library not named"} / ${record.name ?? record.nid} [${record.nid}]${record.kind === "other_provider" ? " → " + record.providers.join(", ") : ""}`);
  }
  if (report.warnings.length) lines.push("", ...report.warnings);
  lines.push("", "Scope and limits", ...report.coverage);
  return lines.join("\n");
}
