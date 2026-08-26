// The hermetic half of e2e-allowance: prove the reproduce path is not a dead end.
//
// WHY THIS EXISTS. `demo.js` is the on-chain half of the custody claim -- it shows that even a
// COMPLYING agent is stopped by the audited program's cap, which is the half the injection
// transcript cannot show. Four published documents point a stranger at it as a reproduce command
// (`README.md`, `TESTING.md`, `docs/DEVNET-PROOF.md`, `docs/MAINNET-PROOF.md`).
//
// It cannot run in CI, and that exclusion is correct rather than an oversight: it needs a FUNDED
// keypair via `E2E_FUNDER` and a live cluster. Handing a funded key to a publicly-triggerable
// workflow is the exact shape this repo removed elsewhere, and it would spend real devnet SOL on
// every push. So the live run stays out on purpose.
//
// What the exclusion ALSO removed, silently, is every check that needs neither funds nor network.
// Nothing in any of the seven workflows named `e2e-allowance`, so a syntax error, a doc that tells
// a stranger to set a variable the script ignores, or a program id that drifts from the one the
// docs cite would all ship green. That is the gap this closes, and it closes only the part that is
// honestly checkable offline. It reads no network and installs nothing.
//
// Every constant is extracted FROM `demo.js` rather than restated here, so this file cannot become
// a second place the truth has to be maintained. Its calibration lives in
// `check_reproduce_path_control.js`, which plants one real defect per check and requires this to
// go red: a check never shown to fail cannot distinguish a healthy tree from a blind gate.
//
//   node e2e-allowance/check_reproduce_path.js

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
// The demo path is overridable ONLY so `check_reproduce_path_control.js` can drive this gate
// against a planted defect. Nothing in CI sets it; the default is the real script.
const DEMO = process.env.ZC_DEMO_OVERRIDE || path.join(__dirname, "demo.js");
const src = fs.readFileSync(DEMO, "utf8");

// The documents that hand a stranger this reproduce path. If one is added later and is not
// listed, its claims go unchecked -- which is the failure this whole file is about, so the
// existence of each is asserted rather than tolerated.
const DOCS = [
  "README.md",
  "TESTING.md",
  path.join("docs", "DEVNET-PROOF.md"),
  path.join("docs", "MAINNET-PROOF.md"),
  path.join("e2e-allowance", "README.md"),
];

let failures = 0;
const fail = (m) => { console.error(`  FAIL  ${m}`); failures++; };
const ok = (m) => console.log(`  ok    ${m}`);

const docText = {};
for (const rel of DOCS) {
  const p = path.join(ROOT, rel);
  if (!fs.existsSync(p)) { fail(`${rel} is listed as a reproduce surface but does not exist`); continue; }
  docText[rel] = fs.readFileSync(p, "utf8");
}
const allDocs = Object.values(docText).join("\n");

// ---------------------------------------------------------------------------
// 1. The program id the script SIGNS AGAINST is the one the docs tell a reader to audit.
//
// This is the load-bearing one. The whole custody argument is "an audited third-party program
// enforces the cap, not our code" -- and that argument is only checkable if the id in the docs is
// the id the script actually uses. A drift here would leave every document citing a program the
// demo never touches, and no test anywhere would notice.
// ---------------------------------------------------------------------------
const idMatch = src.match(/new web3\.PublicKey\('([1-9A-HJ-NP-Za-km-z]{32,44})'\)/);
if (!idMatch) {
  fail("ANCHOR MISSING: cannot find the SF program id in demo.js; this gate is blind, fix the anchor");
} else {
  const programId = idMatch[1];

  // Scan with a DELIBERATELY BROAD character class rather than a base58 one. A drifted id is
  // usually mistyped rather than validly re-encoded, and a base58 class silently truncates at the
  // first illegal character -- `De1egWRONG...` stops at `De1egWR`, falls under any length filter,
  // and the drift reads as clean. The scan has to be able to see a MALFORMED id, because that is
  // the shape a real drift takes.
  //
  // Truncated prefixes are legitimate and common in prose (`De1egAFMk...`), so the test is
  // PREFIX-OF rather than equality: anything long enough to identify a program must be the start
  // of the real one. That accepts every honest abbreviation and rejects every substitution.
  const MIN = 10;
  let citedAnywhere = false;
  const before = failures;
  for (const rel of Object.keys(docText)) {
    for (const tok of docText[rel].match(/De1eg[0-9A-Za-z]*/g) || []) {
      if (tok.length < MIN) continue;
      if (programId.startsWith(tok)) { citedAnywhere = true; continue; }
      fail(`${rel} cites ${tok}, which is not ${programId} that demo.js signs against`);
    }
  }
  if (failures > before) {
    // A per-document mismatch was already reported above; do not also print a pass for the
    // same check, which would put a FAIL and an ok side by side for one question.
  } else if (!citedAnywhere) {
    fail(`no published document cites ${programId}; the audited-program claim is unsourced`);
  } else if (!allDocs.includes(programId)) {
    fail(`the docs only ever abbreviate ${programId}; at least one must give it in full to be auditable`);
  } else {
    ok(`demo.js signs against ${programId}, cited in full and consistently across the docs`);
  }
}

// ---------------------------------------------------------------------------
// 2. The rejection code the script ASSERTS is the one the docs publish, in both notations.
//
// demo.js refuses to call a failed transaction proof unless the failure is specifically the cap
// (`custom !== CAP_ERROR` is fatal there). The docs publish that same code as `0x12c`. Two
// notations for one number in two places is exactly the shape that drifts, so bind them.
// ---------------------------------------------------------------------------
const errMatch = src.match(/const CAP_ERROR = (\d+);/);
if (!errMatch) {
  fail("ANCHOR MISSING: cannot find `const CAP_ERROR` in demo.js; this gate is blind, fix the anchor");
} else {
  const capError = Number(errMatch[1]);
  const hex = `0x${capError.toString(16)}`;
  if (!allDocs.includes(hex)) {
    fail(`demo.js asserts custom error ${capError} (${hex}) but no document publishes ${hex}`);
  } else if (!allDocs.includes(String(capError))) {
    fail(`the docs publish ${hex} but never state its decimal ${capError}; a reader cannot match it to a log`);
  } else {
    ok(`demo.js asserts custom error ${capError}, published as ${hex} and as ${capError}`);
  }
}

// ---------------------------------------------------------------------------
// 3. Every env var the docs tell a stranger to set is one the script actually reads.
//
// A documented variable the script ignores is the quietest way a reproduce path dies: the reader
// sets it, the run does something else, and nothing errors. Direction matters -- the script may
// read MORE than the docs mention (an undocumented override is fine), but a documented variable
// that reaches nothing is a dead end.
// ---------------------------------------------------------------------------
const readVars = new Set((src.match(/process\.env\.([A-Z0-9_]+)/g) || []).map((m) => m.split(".").pop()));
const documentedVars = new Set((allDocs.match(/\bE2E_[A-Z0-9_]+/g) || []));
if (documentedVars.size === 0) {
  fail("no E2E_* variable is documented anywhere; either the docs lost the reproduce command or this scan is broken");
} else {
  const dead = [...documentedVars].filter((v) => !readVars.has(v));
  if (dead.length) fail(`documented but never read by demo.js: ${dead.join(", ")}`);
  else ok(`all ${documentedVars.size} documented E2E_* variables are read by demo.js`);
}

// ---------------------------------------------------------------------------
// 4. Every module demo.js requires is declared in package.json.
//
// `npm install` is step one of the published command. A require that package.json does not
// declare fails at that first step, for the reader and never for us, because our own tree has a
// gitignored node_modules that happens to contain it.
// ---------------------------------------------------------------------------
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
const declared = new Set(Object.keys(pkg.dependencies || {}));
const builtin = new Set(["fs", "path", "os", "crypto", "buffer", "util", "assert"]);
const required = (src.match(/require\(['"]([^'"]+)['"]\)/g) || [])
  .map((m) => m.match(/require\(['"]([^'"]+)['"]\)/)[1])
  .filter((m) => !m.startsWith(".") && !builtin.has(m) && !m.startsWith("node:"));
const undeclared = [...new Set(required)].filter((m) => !declared.has(m));
if (undeclared.length) fail(`demo.js requires ${undeclared.join(", ")}, absent from package.json dependencies`);
else ok(`all ${new Set(required).size} third-party requires are declared in package.json`);

// ---------------------------------------------------------------------------
if (failures) {
  console.error(`\n${failures} check(s) failed. The published reproduce path for the on-chain cap` +
    " claim no longer matches the script a reader is pointed at.");
  process.exit(1);
}
console.log(`
ok  the e2e-allowance reproduce path holds across ${DOCS.length} published documents.`);
