#!/usr/bin/env node
// The pinned reference grader installs, and can produce BOTH verdicts. Offline after `npm ci`.
//
// WHY THIS EXISTS, and it is not a second copy of validate-challenge.mjs.
//
// `validate-challenge.mjs` is the command four published documents point a stranger at, and it
// cannot run without a SUBJECT: with no argument it fetches the live endpoint, so it is a live
// check by construction. That makes it unrunnable as a required CI step, and it is why this
// reproduce path was referenced by ZERO workflows while being published six times.
//
// What CAN be answered on a runner, with no endpoint, is the half that makes a PASS mean
// anything: does `npm ci` resolve the pinned grader at all, and does that grader demonstrably
// REJECT something as well as accept something. A validator never shown to reject has not been
// shown to work, and until this step existed nothing on a runner had ever loaded @x402/core.
//
// THE GRID IS THE CONTROL. The pre-cutover body fails for TWO independent reasons, measured
// rather than assumed: a missing top-level `resource`, and a v1 friendly `network` instead of
// CAIP-2. Each is varied alone, so exactly one of four cases may be accepted. A grader that
// rejects everything fails case 4; one that accepts everything fails cases 1-3; one that checks
// only a single field fails case 2 or case 3. No single-case test can tell those apart.
//
//   cd scripts/x402-validator && npm ci --silent && node check_schema_control.mjs

import { readFile } from 'node:fs/promises'
import { PaymentRequiredV2Schema } from '@x402/core/schemas'

const PKG = new URL('./package.json', import.meta.url)
const DEP = new URL('./node_modules/@x402/core/package.json', import.meta.url)

// The offer, minus the one field each case varies. Values are the deployed node's own, so a
// rejection here is about the field under test rather than about an invented payload.
const OFFER = {
  scheme: 'exact',
  asset: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
  payTo: 'C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ',
  amount: '1000000',
  maxTimeoutSeconds: 60,
  description: 'one feed reading',
}
const RESOURCE = {
  url: 'https://x402.perfpilot.dev/reading',
  description: 'One device-signed reading from a ZeroClaw DePIN feed on Solana',
  mimeType: 'application/json',
}
const FRIENDLY = 'solana-devnet'                              // the pre-cutover v1 form
const CAIP2 = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'       // the current form

const body = (network, resource) => ({
  x402Version: 2,
  ...(resource ? { resource: RESOURCE } : {}),
  accepts: [{ ...OFFER, network }],
  extra: { memo: 'x402-0000000000000000-00' },
})

const CASES = [
  ['the pre-cutover body, friendly network and no resource', body(FRIENDLY, false), false],
  ['CAIP-2 network but still no resource', body(CAIP2, false), false],
  ['a resource but still the friendly network', body(FRIENDLY, true), false],
  ['both corrected, the shape the node serves today', body(CAIP2, true), true],
]

let failures = 0
const report = (ok, line) => {
  if (!ok) failures += 1
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${line}`)
}

// THE PIN ITSELF. `npm ci` honours the lockfile, so a mismatch here means the lockfile and the
// manifest disagree, which is the silent resolution drift `--locked` guards against for crates.
const pinned = JSON.parse(await readFile(PKG, 'utf8')).dependencies['@x402/core']
let installed
try {
  installed = JSON.parse(await readFile(DEP, 'utf8')).version
} catch {
  console.log('FAIL  @x402/core is not installed. Run `npm ci` in this directory first.')
  process.exit(1)
}
report(
  installed === pinned,
  `the installed grader is the pinned one (package.json ${pinned}, installed ${installed})`,
)

for (const [label, subject, mustPass] of CASES) {
  const r = PaymentRequiredV2Schema.safeParse(subject)
  report(
    r.success === mustPass,
    `${mustPass ? 'ACCEPTED' : 'REJECTED'}: ${label}` +
      (r.success === mustPass ? '' : `  (schema said ${r.success}, required ${mustPass})`),
  )
}

console.log(
  `\n${failures ? 'FAIL' : 'PASS'}  ${CASES.length + 1 - failures} of ${CASES.length + 1} checks, ` +
    `${CASES.filter((c) => !c[2]).length} of which require a REJECTION`,
)
process.exit(failures ? 1 : 0)
