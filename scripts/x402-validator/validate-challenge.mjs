#!/usr/bin/env node
// Validate this project's x402 challenge against the PUBLISHED reference schema.
//
// The point of this script is that the grader is not ours. It is @x402/core's own
// PaymentRequiredV2Schema, pinned exactly, so a passing result is a statement about the
// protocol rather than about a check we wrote to suit ourselves.
//
//   npm ci --silent && node validate-challenge.mjs                  # live endpoint
//   node validate-challenge.mjs ./some-captured-body.json           # a captured body
//
// Exit 0 only if BOTH hold: the control failed, and the subject passed.

import { readFile } from 'node:fs/promises'
import { PaymentRequiredV2Schema } from '@x402/core/schemas'

const LIVE = 'https://x402.perfpilot.dev/price'

// HISTORICAL CONTROL, recorded from this endpoint before 2026-08-04 22:51 UTC.
// It MUST fail. Do not "fix" it to match the current body: a validator that has never
// been shown to reject anything has not been shown to work, and this is the only thing
// in the file that proves the PASS below means something.
const CONTROL_PRE_CUTOVER = {
  x402Version: 2,
  accepts: [{
    scheme: 'exact',
    network: 'solana-devnet',                 // v1 friendly form, not CAIP-2
    asset: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    payTo: 'C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ',
    amount: '1000000',
    maxTimeoutSeconds: 60,
    description: 'one feed reading',
  }],
  extra: { memo: 'x402-18c8b63cb32a0a16-a1' }, // no top-level `resource` at all
}

function validate(label, body, mustPass) {
  const r = PaymentRequiredV2Schema.safeParse(body)
  const ok = r.success === mustPass
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`)
  console.log(`        schema valid = ${r.success}, required = ${mustPass}`)
  if (!r.success) {
    for (const i of r.error.issues.slice(0, 8)) {
      console.log(`        - ${i.path.join('.') || '(root)'}: ${i.message}`)
    }
  }
  return ok
}

const arg = process.argv[2]
let subject, source
if (arg) {
  subject = JSON.parse(await readFile(arg, 'utf8'))
  source = arg
} else {
  const res = await fetch(LIVE)
  if (res.status !== 402) {
    console.log(`FAIL  expected HTTP 402 from ${LIVE}, got ${res.status}`)
    process.exit(1)
  }
  subject = await res.json()
  source = `${LIVE} (HTTP 402)`
}

console.log(`subject: ${source}`)
console.log(`grader : @x402/core PaymentRequiredV2Schema (pinned, see package.json)\n`)

const controlOk = validate('CONTROL, the pre-cutover body, must be REJECTED', CONTROL_PRE_CUTOVER, false)
const subjectOk = validate('SUBJECT, the current challenge, must be ACCEPTED', subject, true)

// The schema also accepts a resource.url of http://localhost:4577/reading, so a green
// schema is not evidence that the deployed resource URL is the public one. Read it.
const url = subject?.resource?.url ?? '(absent)'
const publicUrl = String(url).startsWith('https://x402.perfpilot.dev')
console.log(`\n${publicUrl ? 'PASS' : 'FAIL'}  resource.url is the public endpoint, not a localhost default`)
console.log(`        resource.url = ${url}`)

const nets = (subject.accepts ?? []).map((a) => a.network)
const allCaip = nets.length > 0 && nets.every((n) => String(n).startsWith('solana:'))
console.log(`${allCaip ? 'PASS' : 'FAIL'}  every accepts[].network is CAIP-2`)
for (const n of nets) console.log(`        ${n}`)

const verdict = controlOk && subjectOk && publicUrl && allCaip
console.log(`\nVERDICT: ${verdict ? 'PASS' : 'FAIL'}`)
process.exit(verdict ? 0 : 1)
