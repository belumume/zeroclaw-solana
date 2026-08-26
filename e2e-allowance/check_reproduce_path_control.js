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
    expect: "no published document cites",
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
console.log(`\nok  all ${mutants.length} planted defects detected, over a passing baseline.`);
