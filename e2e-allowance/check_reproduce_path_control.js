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

// The five documents the gate reads.
const ALL_DOCS = ["README.md", "TESTING.md", "docs/DEVNET-PROOF.md",
                  "docs/MAINNET-PROOF.md", "e2e-allowance/README.md"];

// THE DOC MUTANTS RUN ON COPIES. They used to be planted in the TRACKED documents in the live
// working tree and restored in a `finally`, which is clean for a run that completes and unsafe
// for one that does not: a SIGINT, an OOM or a CI step timeout between the write and the restore
// leaves a planted WRONG PROGRAM ID sitting in five published documents, where the next reader --
// or the next gate, or a concurrent agent sharing this tree -- meets it as real. The demo side
// already had this seam via ZC_DEMO_OVERRIDE; the doc side did not, so it got one. Nothing here
// writes inside the repository any more.
const DOCS_SANDBOX = path.join(tmpdir, "docs-root");
for (const rel of ALL_DOCS) {
  const dst = path.join(DOCS_SANDBOX, rel);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(path.join(ROOT, rel), dst);
}

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
  const abs = path.join(DOCS_SANDBOX, relDoc);
  const original = fs.readFileSync(abs, "utf8");
  if (!original.includes(from)) {
    return { code: null, out: `anchor ${from} absent from ${relDoc}` };
  }
  try {
    fs.writeFileSync(abs, original.split(from).join(to), "utf8");
    const r = spawnSync(process.execPath, [GATE], {
      env: { ...process.env, ZC_DOCS_ROOT: DOCS_SANDBOX },
      encoding: "utf8",
    });
    return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
  } finally {
    // Restore the SANDBOX copy so the next mutant starts from a clean one. The tracked document
    // it was copied from is never touched, so an interrupt here costs nothing.
    fs.writeFileSync(abs, original, "utf8");
  }
}

let bad = 0;
// Counted rather than computed from `mutants.length`. The failure line used to print
// `${bad} of ${mutants.length}` while `bad` could be incremented from ten places, so seven
// failures rendered as "7 of 6" -- and that line is the ONE a reader only ever sees when
// something is already broken. A counter incremented beside every verdict cannot drift when a
// mutant or a control is added, which an expression assembled by hand can and did.
let checked = 0;

// Byte state of the tracked documents BEFORE anything runs. Asserted again at the end: the doc
// mutants are supposed to touch only the sandbox copies now, and "supposed to" is not evidence.
const trackedBefore = ALL_DOCS.map((rel) => fs.readFileSync(path.join(ROOT, rel), "utf8"));

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

  // --- the constants are WIRED, not merely present -----------------------------------
  // These four are the direction every check above was blind to. Each keeps the constant the
  // doc-agreement checks read, so all of those still print ok while the script proves nothing.
  {
    name: "the whole wrong-reason guard is deleted while `const CAP_ERROR` stays",
    src: pristine.replace(/ {2}if \(custom !== CAP_ERROR\) \{[\s\S]*?\n {2}\}\n/, ""),
    expect: "never COMPARED against anything",
  },
  {
    name: "the wrong-reason branch stops refusing (comparison kept, exit removed)",
    src: pristine.replace(/(if \(custom !== CAP_ERROR\) \{[\s\S]*?)\n {4}process\.exit\(1\);/, "$1"),
    expect: "does not exit non-zero",
  },
  {
    name: "the transfer is addressed to an undeclared program instead of the audited one",
    src: pristine.replace(
      "programId: SF, data: Buffer.concat([Buffer.from([4])",
      "programId: NOT_THE_AUDITED_PROGRAM, data: Buffer.concat([Buffer.from([4])"),
    expect: "undeclared program",
  },
  {
    // Discriminates the DERIVED family prefix from the hardcoded `De1eg` it replaced: against the
    // old literal this mutant reported a doc mismatch (`cites ... which is not`), which reads as
    // the docs being wrong. Only a derived prefix reports the truth -- the id demo.js now signs
    // against is cited by nobody.
    name: "the program id moves to a different base58 family (only a DERIVED prefix says why)",
    src: pristine.replace(
      /const SF = new web3\.PublicKey\('[1-9A-HJ-NP-Za-km-z]{32,44}'\);/,
      "const SF = new web3.PublicKey('Xyz9uKpQmT4vR7sLwN2hFbGdJc5aE8zYkM3nPqSt6Uv');"),
    expect: "no published document cites",
  },

  // --- the module scan is not blind ----------------------------------------------------
  {
    // THE FAIL-OPEN THIS FILE EXISTS TO PIN. Before the fix this printed
    // `ok all 0 third-party requires are declared` and exited 0 -- a green over a scan that had
    // read nothing. Note it re-supplies NO anchor: that is the point, since a mutant that hands
    // the gate a replacement to find cannot detect a scan that stopped finding anything.
    name: "every third-party module load stops matching (the fail-open that printed `all 0`)",
    src: pristine
      .replace("const web3 = require('@solana/web3.js');", "const web3 = globalThis.__web3;")
      .replace("const spl = require('@solana/spl-token');", "const spl = globalThis.__spl;"),
    expect: "SCAN BLIND",
  },
  {
    name: "an undeclared package is loaded by dynamic import() rather than require()",
    src: pristine.replace(
      "const fs = require('fs');",
      "const fs = require('fs');\nasync function lazy() { return await import('@solana/not-a-declared-package'); }"),
    expect: "absent from package.json dependencies",
  },
  {
    name: "module resolution is indirected through createRequire",
    src: pristine.replace(
      "const web3 = require('@solana/web3.js');",
      "const { createRequire } = require('node:module');\nconst _r = createRequire(__filename);\nconst web3 = _r('@solana/web3.js');"),
    expect: "cannot see what it loads",
  },
];

// --- doc-side mutants: the OTHER half of the agreement -------------------------------
// Derived from demo.js, not written out. A literal here is a second copy of the id that outlives
// the thing it describes, which is the same defect this pass removed from the gate's doc scan.
const REAL_ID = (pristine.match(/const SF = new web3\.PublicKey\('([1-9A-HJ-NP-Za-km-z]{32,44})'\)/) || [])[1];
if (!REAL_ID) {
  console.error("FAIL  cannot read the program id out of demo.js; every doc mutant below would be");
  console.error("      planted against an anchor that is not there, and would report a false miss.");
  process.exit(2);
}
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
  // THE LAST TWO BRANCHES OF THE ID CHECK, which no mutant above can reach.
  //
  // Every per-document mutant plants a WRONG id in ONE file, so the per-doc "which is not"
  // failure fires and the gate short-circuits before either of these. They are only
  // reachable when every document is consistent AND the full id is absent, so both have to
  // edit all five at once. Measured while writing them: all five documents cite the id in
  // full and none abbreviates it, so each mutant lands on exactly one branch.
  {
    name: "every document abbreviates the id and none gives it in full",
    doc: "*",
    from: REAL_ID,
    // A valid prefix, comfortably over the gate's MIN of 10. Each token still satisfies
    // programId.startsWith(tok), so nothing is reported as a wrong id and the run reaches the
    // question this branch asks: is it auditable anywhere.
    to: REAL_ID.slice(0, 20),
    expect: "only ever abbreviate",
  },
  {
    name: "no document cites the id at all, so the audited-program claim is unsourced",
    doc: "*",
    // Cut below MIN, so the scan skips every remaining token as too short to be a citation
    // rather than reporting it as a mismatch. That is the difference between this branch and
    // the one above: there the id is cited and truncated, here it is not cited.
    from: REAL_ID,
    to: REAL_ID.slice(0, 5),
    expect: "no published document cites",
  },
];

function runGateWithAllDocsEdited(from, to) {
  const saved = ALL_DOCS.map((rel) => {
    const abs = path.join(DOCS_SANDBOX, rel);
    return { abs, text: fs.readFileSync(abs, "utf8") };
  });
  try {
    let touched = 0;
    for (const s of saved) {
      if (s.text.includes(from)) { fs.writeFileSync(s.abs, s.text.split(from).join(to), "utf8"); touched++; }
    }
    if (touched === 0) return { code: null, out: `anchor ${from} absent from every document` };
    const r = spawnSync(process.execPath, [GATE], {
      env: { ...process.env, ZC_DOCS_ROOT: DOCS_SANDBOX },
      encoding: "utf8",
    });
    return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
  } finally {
    for (const s of saved) fs.writeFileSync(s.abs, s.text, "utf8");
  }
}

for (const m of docMutants) {
  checked++;
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
  checked++;
  const r = runGateWithDocEdit("e2e-allowance/README.md", REAL_ID, "De1egAFMkMWZ");
  if (r.code === 0) console.log("  ok    control: a truncated prefix is still accepted");
  else { console.error("  FAIL  control: a legitimate truncated prefix was rejected (over-correction)"); bad++; }
}

// OVER-CORRECTION CONTROL for the programId wiring check. A demo.js that grows a direct SPL
// instruction during setup is CORRECT, and a rule demanding every instruction be addressed to the
// audited program would go red on it and blame the change. The allowlist exists for exactly this,
// and this control is what stops it being asserted rather than demonstrated.
{
  checked++;
  const legit = pristine.replace(
    "  const transferIx = amount =>",
    "  const setupIx = new web3.TransactionInstruction({ programId: spl.TOKEN_PROGRAM_ID, data: Buffer.from([0]), keys: [] });\n  const transferIx = amount =>");
  if (legit === pristine) {
    console.error("  FAIL  control: could not plant a legitimate support instruction; the anchor moved");
    bad++;
  } else {
    const r = runGate(legit);
    if (r.code === 0) console.log("  ok    control: a declared support program is still accepted");
    else { console.error("  FAIL  control: a legitimate spl.TOKEN_PROGRAM_ID instruction was rejected (over-correction)"); bad++; }
  }
}

// CORRECTNESS CONTROL for check 1's anchor, and it is here because it caught a wrong fix rather
// than because it was foreseen. The anchor used to take the first pubkey literal in the file; the
// first repair anchored on "a const binding", which sounds equivalent and is not -- with a decoy
// `const USDC = ...` one line above `const SF`, a shape-anchored regex still resolved to the MINT
// and the gate went on to report the docs as citing the wrong program. Only anchoring on the name
// works, and this is what proves it stays that way. Exit code alone would not discriminate, so
// the id in the output is what is asserted.
{
  checked++;
  const decoy = pristine.replace(
    "const SF = new web3.PublicKey('",
    "const USDC = new web3.PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');\nconst SF = new web3.PublicKey('");
  if (decoy === pristine) {
    console.error("  FAIL  control: could not plant a decoy pubkey const; the anchor moved");
    bad++;
  } else {
    const r = runGate(decoy);
    if (r.code === 0 && r.out.includes(`signs against ${REAL_ID}`)) {
      console.log("  ok    control: a decoy pubkey const above SF does not re-point check 1");
    } else {
      console.error("  FAIL  control: a decoy pubkey const above SF re-pointed check 1 at the wrong key");
      bad++;
    }
  }
}

for (const m of mutants) {
  checked++;
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

// THE CONTROL ON THE CONTROL. Every doc mutant above is supposed to have edited a sandbox copy
// and left the published documents alone. That is a claim about this harness, so it is checked
// rather than trusted: a regression that pointed a mutant back at ROOT would otherwise be
// invisible here and visible only as an unexplained diff in someone's working tree.
{
  checked++;
  const drifted = ALL_DOCS.filter((rel, i) => fs.readFileSync(path.join(ROOT, rel), "utf8") !== trackedBefore[i]);
  if (drifted.length) {
    console.error(`  FAIL  this harness modified tracked document(s): ${drifted.join(", ")}.` +
      " A doc mutant is writing to the working tree instead of the sandbox copy.");
    bad++;
  } else {
    console.log(`  ok    control: all ${ALL_DOCS.length} published documents are byte-identical; nothing was planted in the tree`);
  }
}

fs.rmSync(tmpdir, { recursive: true, force: true });

if (bad) {
  console.error(`\n${bad} of ${checked} calibration check(s) failed.` +
    " check_reproduce_path.js is not calibrated and its green is not evidence.");
  process.exit(1);
}
console.log(`\nok  ${checked} calibration checks pass: ${mutants.length} planted defects in demo.js and ` +
  `${docMutants.length} in the docs all detected, over a passing baseline, with ` +
  `${checked - mutants.length - docMutants.length} over-correction/integrity controls still green.`);
