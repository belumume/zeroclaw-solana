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

// The DOC root is overridable for the same reason, and it is not symmetry for its own sake. This
// gate is an AGREEMENT check, so calibrating it means planting a defect on the doc side too --
// and without this seam the control could only do that by editing the published documents IN THE
// WORKING TREE. A full control run restores them, but a SIGINT, an OOM or a step timeout between
// write and restore would leave a planted wrong program id sitting in five tracked documents,
// where the next reader or gate meets it as real. The demo side already had this seam; the doc
// side ran on the live tree. Nothing in CI sets either.
const DOCS_ROOT = process.env.ZC_DOCS_ROOT || ROOT;

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
  const p = path.join(DOCS_ROOT, rel);
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
// Anchor on the NAME, exactly as check 2 anchors on `CAP_ERROR`. This used to take the FIRST
// `new web3.PublicKey('...')` in the file, which is unique TODAY only because demo.js's other two
// PublicKeys take a variable. Any literal constant added above `const SF` -- a mint address, a
// second program -- silently re-points this entire check at that key instead, and it then reports
// four CORRECT documents as citing a wrong id. A legitimate edit turning the gate red and blaming
// the docs is the worst failure shape available here.
//
// MEASURED while fixing this, because the near-miss is instructive: anchoring on "a const binding"
// rather than on the name does NOT close it. With `const USDC = new web3.PublicKey('EPjFW...')`
// inserted one line above, a shape-anchored regex still resolved to USDC and the gate reported the
// mint as the program the docs must cite. Only the name works.
//
// The cost is that renaming SF trips ANCHOR MISSING rather than following the rename. That is the
// same deliberate trade check 2 makes: a gate that loudly cannot find its anchor is worth far more
// than one that quietly finds the wrong thing.
const ID_BINDING = "SF";
const idMatch = src.match(
  new RegExp(`const ${ID_BINDING} = new web3\\.PublicKey\\('([1-9A-HJ-NP-Za-km-z]{32,44})'\\)`));
let idName = null;
if (!idMatch) {
  fail(`ANCHOR MISSING: cannot find \`const ${ID_BINDING} = new web3.PublicKey('...')\` in demo.js; ` +
    "this gate is blind, fix the anchor");
} else {
  idName = ID_BINDING;
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
  //
  // The family prefix is DERIVED from the id rather than written out. A literal `De1eg` here
  // would be a second place the truth has to be maintained, in the one file whose whole premise
  // is that it maintains none -- and it outlives the id it describes, so the day `demo.js` points
  // at a different program the scan goes on hunting the retired family.
  //
  // HONEST BOUND, because deriving it does NOT close what it looks like it closes: this scan only
  // ever inspects tokens in the id's OWN family, so a document citing a wholly DIFFERENT program
  // (`Xyz99...`) is still invisible to it. Closing that would mean treating every base58-shaped
  // token in the docs as a candidate program id, and these documents are full of mints,
  // addresses and signatures -- an over-correction that would fire on correct prose. What the
  // whole-file checks below do catch is the case that matters most: if NO document cites the id
  // demo.js actually signs against, the audited-program claim is unsourced and this fails.
  const MIN = 10;
  const family = new RegExp(programId.slice(0, 5).replace(/[^0-9A-Za-z]/g, "") + "[0-9A-Za-z]*", "g");
  let citedAnywhere = false;
  const before = failures;
  for (const rel of Object.keys(docText)) {
    for (const tok of docText[rel].match(family) || []) {
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
// 2b. Those constants are WIRED, not merely present.
//
// THE GAP THIS CLOSES, and it is the one that makes the four checks above weaker than they read.
// Every one of them binds a CONSTANT in demo.js to a CONSTANT in the docs. None of them asks
// whether the constant reaches anything. So the whole `if (custom !== CAP_ERROR) { ... exit(1) }`
// block can be deleted while `const CAP_ERROR = 300;` stays, and every check above still agrees:
// the number is defined, the docs publish it, the notations match. `node --check` passes too --
// it parses, it just no longer proves anything. demo.js's own words for that block are that a
// wrong-reason rejection "cannot be published as evidence", and deleting it silently converts
// every failed transaction into a cap proof.
//
// The same question applies to the program id, and there it IS the custody claim: "the audited
// third-party program, not our code, enforces the cap" is false the moment an instruction is
// built against some other programId, however faithfully the docs cite this one.
//
// HONEST BOUND: this asks whether the wiring EXISTS in the source text, not whether it executes.
// A comparison sitting in unreachable code would satisfy it. Whether that branch is reached on a
// live cluster is exactly the half that needs funds and a network, and it stays out.
// ---------------------------------------------------------------------------
if (errMatch) {
  const cmpAt = src.search(/(?:!==|===|!=|==)\s*CAP_ERROR|CAP_ERROR\s*(?:!==|===|!=|==)/);
  if (cmpAt < 0) {
    fail("CAP_ERROR is defined in demo.js but never COMPARED against anything, so the published " +
      "rejection code is decoration and a wrong-reason failure would be published as cap evidence");
  } else if (!/process\.exit\(\s*[1-9]/.test(src.slice(cmpAt, cmpAt + 700))) {
    // 700 chars: the real refusal sits 413 chars past the comparison and the next unrelated
    // non-zero exit is 949 past it, so the window sees this block and not its neighbour.
    fail("demo.js compares against CAP_ERROR but that branch does not exit non-zero; a rejection " +
      "for the WRONG REASON would be reported as a successful cap proof");
  } else {
    ok("CAP_ERROR is compared, and a wrong-reason rejection exits non-zero rather than publishing");
  }
}

// Programs that are legitimately NOT the audited one. This is an ALLOWLIST rather than an
// exact-match rule on purpose: a demo.js that grows a direct SPL or System instruction during
// setup would be perfectly correct, and a check demanding every instruction be addressed to the
// SF program would go red on that and blame a correct change. A newcomer must still be DECLARED
// here, which is what keeps this a check rather than a widening.
const NON_SF_PROGRAMS = new Set([
  "spl.TOKEN_PROGRAM_ID",
  "spl.TOKEN_2022_PROGRAM_ID",
  "spl.ASSOCIATED_TOKEN_PROGRAM_ID",
  "web3.SystemProgram.programId",
]);
if (idName) {
  const uses = [...src.matchAll(/programId:\s*([A-Za-z_$][\w$.]*)/g)].map((m) => m[1]);
  const undeclaredProgram = [...new Set(uses.filter((u) => u !== idName && !NON_SF_PROGRAMS.has(u)))];
  if (!uses.some((u) => u === idName)) {
    fail(`demo.js binds the audited program as ${idName} but addresses no instruction to it; ` +
      "the cap the docs attribute to that program is not the one this script exercises");
  } else if (undeclaredProgram.length) {
    fail(`demo.js builds instruction(s) against an undeclared program: ${undeclaredProgram.join(", ")}. ` +
      `If that is intended, declare it beside ${idName} in NON_SF_PROGRAMS with the reason`);
  } else {
    ok(`every instruction demo.js builds is addressed to ${idName} or a declared support program`);
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
// THIS CHECK USED TO FAIL OPEN, alone among the four. Checks 1 and 2 report ANCHOR MISSING and
// check 3 guards on an empty scan; this one had nothing. An empty `required` yielded an empty
// `undeclared` and printed `ok all 0 third-party requires are declared`, exit 0 -- a green over a
// scan that had read nothing. Anything that stops the literal `require(...)` form matching does
// it: an ESM migration, `createRequire`, requires moved inside a function, or `await import()`.
// `node --check` passes on all of them too, so BOTH steps of the CI job go green over a gate
// covering nothing. Measured before the fix: hiding BOTH of demo.js's packages behind
// `createRequire` and a dynamic `import()` printed `all 0 third-party requires` and exited 0.
//
// So: scan both literal forms, and treat an EMPTY result as a blind scan rather than a pass.
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
const declared = new Set(Object.keys(pkg.dependencies || {}));
const builtin = new Set(["fs", "path", "os", "crypto", "buffer", "util", "assert"]);
const LOADS = /(?:require|import)\(\s*['"]([^'"]+)['"]\s*\)/g;
const required = [...src.matchAll(LOADS)]
  .map((m) => m[1])
  .filter((m) => !m.startsWith(".") && !builtin.has(m) && !m.startsWith("node:"));
const undeclared = [...new Set(required)].filter((m) => !declared.has(m));
if (/createRequire/.test(src)) {
  // A createRequire alias resolves modules through a local binding (`_r('pkg')`), which this
  // scan cannot follow without becoming an interpreter. Say so rather than reporting a count
  // that silently excludes whatever it loads. Either drop the indirection or extend this scan.
  fail("demo.js resolves modules through createRequire; this scan cannot see what it loads, so " +
    "its result would be a number that excludes them rather than a check");
} else if (!required.length) {
  fail("SCAN BLIND: demo.js declares no third-party module by literal require() or import(), " +
    "which for a Solana script means the module scan stopped matching rather than that it loads " +
    "nothing; a reader's `npm install` step is now unchecked");
} else if (undeclared.length) {
  fail(`demo.js loads ${undeclared.join(", ")}, absent from package.json dependencies`);
} else {
  ok(`all ${new Set(required).size} third-party modules loaded by demo.js are declared in package.json`);
}

// ---------------------------------------------------------------------------
if (failures) {
  console.error(`\n${failures} check(s) failed. The published reproduce path for the on-chain cap` +
    " claim no longer matches the script a reader is pointed at.");
  process.exit(1);
}
console.log(`
ok  the e2e-allowance reproduce path holds across ${DOCS.length} published documents.`);
