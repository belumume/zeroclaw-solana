// Calibration for `check_reproduce_path.js`: prove it can go RED, one planted defect per check.
//
// WHY THIS EXISTS. A gate that has only ever printed ok is indistinguishable from a gate whose
// anchors stopped matching -- both emit the same clean output, and the reassuring reading is
// always available. The four checks next door are all regex anchors into `demo.js`, which is
// exactly the shape that silently stops matching when the file it reads is edited. So each one is
// driven here against a copy of `demo.js` with a real defect planted in it, and is required to
// report the failure.
//
// The PRISTINE baseline runs first and must be green. Without that, a harness where every mutant
// fails for some unrelated reason -- a bad temp path, a missing doc -- would look like perfect
// detection while testing nothing.
//
//   node e2e-allowance/check_reproduce_path_control.js

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const GATE = path.join(__dirname, "check_reproduce_path.js");
const ROOT = path.join(__dirname, "..");
const DEMO = path.join(__dirname, "demo.js");
const pristine = fs.readFileSync(DEMO, "utf8");
const tmpdir = fs.mkdtempSync(path.join(os.tmpdir(), "zc-e2e-allowance-control-"));

function runGate(demoSource) {
  const p = path.join(tmpdir, "demo.js");
  fs.writeFileSync(p, demoSource, "utf8");
  const r = spawnSync(process.execPath, [GATE], {
    env: { ...process.env, ZC_DEMO_OVERRIDE: p },
    encoding: "utf8",
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

// THE DOC SIDE NEEDS ITS OWN MUTANTS. This is an AGREEMENT gate, so it has two sides, and every
// mutant above edits demo.js. A hole survived exactly there: a drifted id planted in a document
// went undetected, because the scan used a base58 character class that truncated a mistyped id
// below the length filter while other documents still carried the correct one. It was found by
// probing the untested direction, not by anything failing, which is the whole argument for
// mutating both sides rather than the convenient one.
function runGateWithDocEdit(relDoc, from, to) {
  const abs = path.join(ROOT, relDoc);
  const original = fs.readFileSync(abs, "utf8");
  if (!original.includes(from)) {
    return { code: null, out: `anchor ${from} absent from ${relDoc}` };
  }
  try {
    fs.writeFileSync(abs, original.split(from).join(to), "utf8");
    const r = spawnSync(process.execPath, [GATE], { encoding: "utf8" });
    return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
  } finally {
    // Restore unconditionally. A harness that mutates tracked files and throws would leave the
    // working tree edited, and the next reader would meet a planted defect as if it were real.
    fs.writeFileSync(abs, original, "utf8");
  }
}

let bad = 0;

// --- baseline: the harness itself must be able to produce a PASS ---------------------
const base = runGate(pristine);
if (base.code !== 0) {
  console.error("FAIL  baseline: the gate does not pass on the pristine demo.js, so every mutant");
  console.error("      below would 'fail' for reasons that have nothing to do with its defect.");
  console.error(base.out);
  process.exit(2);
}
console.log("  ok    baseline: pristine demo.js passes, so a red below is attributable to the mutant");

// --- mutants: each must be DETECTED ---------------------------------------------------
// `expect` is a substring the gate's own output must contain, so a mutant that goes red for an
// unrelated reason does not count as detection. Exit code alone is not enough.
const mutants = [
  {
    name: "program id drifts from the one the docs cite",
    src: pristine.replace(
      /new web3\.PublicKey\('[1-9A-HJ-NP-Za-km-z]{32,44}'\)/,
      "new web3.PublicKey('De1egZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ')"),
    expect: "which is not",
  },
  {
    name: "the program id anchor stops matching entirely",
    src: pristine.replace(/const SF = new web3\.PublicKey\([^)]*\);/, "const SF = getProgramId();"),
    expect: "ANCHOR MISSING",
  },
  {
    name: "rejection code drifts from the published 0x12c",
    src: pristine.replace(/const CAP_ERROR = \d+;/, "const CAP_ERROR = 999;"),
    expect: "no document publishes 0x3e7",
  },
  {
    name: "the rejection-code anchor stops matching entirely",
    src: pristine.replace(/const CAP_ERROR = \d+;/, "const CAP_ERROR = someLookup();"),
    expect: "ANCHOR MISSING",
  },
  {
    name: "a documented variable stops being read",
    // E2E_MINT is named in docs/DEVNET-PROOF.md's reproduce command. Stop reading it and the
    // reader's setting silently does nothing, which is the dead-end this check exists for.
    src: pristine.replace(/process\.env\.E2E_MINT/g, "undefined"),
    expect: "documented but never read",
  },
  {
    name: "a require is added that package.json does not declare",
    src: pristine.replace(
      /const fs = require\('fs'\);/,
      "const fs = require('fs');\nconst x = require('@solana/not-a-declared-package');"),
    expect: "absent from package.json dependencies",
  },
];

// --- doc-side mutants: the OTHER half of the agreement -------------------------------
const REAL_ID = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44";
const docMutants = [
  {
    name: "a document cites a MALFORMED wrong id (the case that once slipped through)",
    doc: "e2e-allowance/README.md",
    from: REAL_ID,
    to: "De1egWRONGWRONGWRONGWRONGWRONGWRONGWRONGWRO",
    expect: "which is not",
  },
  {
    name: "a document cites a well-formed but wrong id",
    doc: "e2e-allowance/README.md",
    from: REAL_ID,
    to: "De1eg99999999999999999999999999999999999999",
    expect: "which is not",
  },
  // NOT per-document, and deliberately so. The docs legitimately carry other custom error codes
  // (0x1770 and 0x1771 appear in DEVNET-PROOF.md), so a rule demanding every hex in every file be
  // 0x12c would fire on correct prose -- an over-correction worse than the gap it closes. What the
  // check promises is that the code demo.js ASSERTS is published SOMEWHERE auditable, so the
  // mutant that tests that promise removes it from every document at once.
  {
    name: "the published rejection code disappears from every document",
    doc: "*",
    from: "0x12c",
    to: "0xDEAD",
    expect: "no document publishes 0x12c",
  },
];

// The five documents the gate reads, so a "*" mutant can edit them together.
const ALL_DOCS = ["README.md", "TESTING.md", "docs/DEVNET-PROOF.md",
                  "docs/MAINNET-PROOF.md", "e2e-allowance/README.md"];

function runGateWithAllDocsEdited(from, to) {
  const saved = ALL_DOCS.map((rel) => {
    const abs = path.join(ROOT, rel);
    return { abs, text: fs.readFileSync(abs, "utf8") };
  });
  try {
    let touched = 0;
    for (const s of saved) {
      if (s.text.includes(from)) { fs.writeFileSync(s.abs, s.text.split(from).join(to), "utf8"); touched++; }
    }
    if (touched === 0) return { code: null, out: `anchor ${from} absent from every document` };
    const r = spawnSync(process.execPath, [GATE], { encoding: "utf8" });
    return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
  } finally {
    for (const s of saved) fs.writeFileSync(s.abs, s.text, "utf8");
  }
}

for (const m of docMutants) {
  const r = m.doc === "*"
    ? runGateWithAllDocsEdited(m.from, m.to)
    : runGateWithDocEdit(m.doc, m.from, m.to);
  if (r.code === null) {
    console.error(`  FAIL  doc mutant "${m.name}": ${r.out}`);
    bad++;
  } else if (r.code === 0) {
    console.error(`  FAIL  doc mutant "${m.name}" was NOT detected; that direction proves nothing`);
    bad++;
  } else if (!r.out.includes(m.expect)) {
    console.error(`  FAIL  doc mutant "${m.name}" went red, but not for its own reason`);
    bad++;
  } else {
    console.log(`  ok    detected: ${m.name}`);
  }
}

// OVER-CORRECTION CONTROL. A legitimate truncated prefix is how these ids are written in prose,
// and a check that rejects one would be worse than the hole it closes.
{
  const r = runGateWithDocEdit("e2e-allowance/README.md", REAL_ID, "De1egAFMkMWZ");
  if (r.code === 0) console.log("  ok    control: a truncated prefix is still accepted");
  else { console.error("  FAIL  control: a legitimate truncated prefix was rejected (over-correction)"); bad++; }
}

for (const m of mutants) {
  if (m.src === pristine) {
    console.error(`  FAIL  mutant "${m.name}" changed nothing; its pattern no longer matches demo.js`);
    bad++;
    continue;
  }
  const r = runGate(m.src);
  if (r.code === 0) {
    console.error(`  FAIL  mutant "${m.name}" was NOT detected; that check proves nothing`);
    bad++;
  } else if (!r.out.includes(m.expect)) {
    console.error(`  FAIL  mutant "${m.name}" went red, but not for its own reason`);
    console.error(`        expected the output to mention: ${m.expect}`);
    bad++;
  } else {
    console.log(`  ok    detected: ${m.name}`);
  }
}

fs.rmSync(tmpdir, { recursive: true, force: true });

if (bad) {
  console.error(`\n${bad} of ${mutants.length} planted defect(s) went undetected.` +
    " check_reproduce_path.js is not calibrated and its green is not evidence.");
  process.exit(1);
}
console.log(`\nok  all ${mutants.length + docMutants.length} planted defects detected on BOTH sides (${mutants.length} in demo.js, ${docMutants.length} in the docs), over a passing baseline.`);
