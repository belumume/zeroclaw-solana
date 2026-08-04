// e2e-allowance: proves the audited SF Allowances program bounds a COMPLYING agent on-chain.
//
// Flow (all real, against the deployed SF program De1egAFMk... on devnet OR mainnet):
//   1. an SPL mint + operator/receiver ATAs, funded operator
//   2. initSubscriptionAuthority, then createFixedDelegation capped, delegatee = a fresh
//      "agent session key"
//   3. the agent session key SIGNS two transferFixed spends:
//        - within cap -> SUCCEEDS
//        - over cap   -> REJECTED on-chain by the program (custom error 0x12c = 300),
//          landed as a failed tx via skipPreflight so it is clickable on the explorer
//
// The program, not the plugin and not the LLM, enforces the cap. This is the fails-closed
// evidence for a COMPLYING model (the agent signed the over-cap spend and the chain stopped it),
// complementing the injection transcript (which shows the model REFUSING).
//
// Run (devnet, self-minted test token, the original behaviour):
//       npm install
//       E2E_FUNDER=/path/to/devnet-keypair.json node demo.js
//
// Run (an EXISTING mint, e.g. real USDC on mainnet):
//       E2E_FUNDER=/path/to/keypair.json \
//       E2E_RPC=https://api.mainnet-beta.solana.com \
//       E2E_CLUSTER=mainnet \
//       E2E_MINT=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v \
//       E2E_CAP=500000 E2E_WITHIN=400000 E2E_OVER=1000000 \
//       node demo.js
//
// WHY THE OVER AMOUNT MUST STAY WITHIN THE BALANCE: if the over-cap attempt also exceeds the
// token balance it can be refused for insufficient funds, and a rejection for the wrong reason
// proves nothing about the cap. This script therefore ASSERTS the failure is custom error 300
// and exits non-zero on any other error, so a wrong-reason rejection cannot be published as
// evidence. What 300 means is sourced to the upstream program in docs/MAINNET-PROOF.md.
const web3 = require('@solana/web3.js');
const spl = require('@solana/spl-token');
const fs = require('fs');

const SF = new web3.PublicKey('De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44');
const RPC = process.env.E2E_RPC || 'https://api.devnet.solana.com';
const CLUSTER = process.env.E2E_CLUSTER || 'devnet';
const MINT_IN = process.env.E2E_MINT || null;
const OP = process.env.E2E_FUNDER;
if (!OP) { console.error('set E2E_FUNDER=<path to a funded keypair json>'); process.exit(1); }

// Base units. Defaults reproduce the original devnet run exactly (6-decimal mint).
const CAP = BigInt(process.env.E2E_CAP || 5_000000);
const WITHIN = BigInt(process.env.E2E_WITHIN || 5_000000);
const OVER = BigInt(process.env.E2E_OVER || 10_000000);
// 0x12c. Named AmountExceedsLimit ("Transfer amount exceeds delegation limit") in the
// solana-foundation program's own errors.rs and IDL, not in anything we wrote. That citation, and
// why replaying a captured message at any amount returns 300 once the delegation has been partly
// spent, are in docs/MAINNET-PROOF.md.
const CAP_ERROR = 300;

const u64le = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64le = n => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };
const explorer = s => `https://explorer.solana.com/tx/${s}` + (CLUSTER === 'mainnet' ? '' : `?cluster=${CLUSTER}`);

async function main() {
  const conn = new web3.Connection(RPC, 'confirmed');
  const operator = web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(OP, 'utf8'))));
  const delegatee = web3.Keypair.generate();  // the agent session key, needs no funds
  // The receiver RECEIVES REAL VALUE, so it must not be ephemeral on a live cluster: a generated
  // keypair is discarded when the process exits, which would permanently destroy the transferred
  // amount. Devnet keeps the old generate-on-the-fly behaviour because the tokens are worthless
  // there; anywhere else demands an address whose key is actually held.
  const RECEIVER_IN = process.env.E2E_RECEIVER || null;
  if (!RECEIVER_IN && CLUSTER !== 'devnet') {
    console.error(`FATAL: cluster is "${CLUSTER}" and no E2E_RECEIVER was given.`);
    console.error('       The default receiver is an ephemeral keypair that is discarded on exit,');
    console.error('       so the transferred amount would be unrecoverable. Pass a held address.');
    process.exit(1);
  }
  const receiverPk = RECEIVER_IN ? new web3.PublicKey(RECEIVER_IN) : web3.Keypair.generate().publicKey;
  const enc = new TextEncoder();
  console.log('cluster :', CLUSTER, RPC);
  console.log('operator (delegator/owner/payer):', operator.publicKey.toBase58());
  console.log('delegatee (agent session key)   :', delegatee.publicKey.toBase58());

  let mint, decimals;
  if (MINT_IN) {
    mint = new web3.PublicKey(MINT_IN);
    decimals = (await spl.getMint(conn, mint)).decimals;
    console.log('using EXISTING mint:', mint.toBase58(), `(${decimals} decimals)`);
  } else {
    mint = await spl.createMint(conn, operator, operator.publicKey, null, 6);
    decimals = 6;
    console.log('created test mint:', mint.toBase58());
  }
  const human = n => (Number(n) / 10 ** decimals).toFixed(decimals).replace(/0+$/, '').replace(/\.$/, '');

  const opAta = (await spl.getOrCreateAssociatedTokenAccount(conn, operator, mint, operator.publicKey)).address;
  const rxAta = (await spl.getOrCreateAssociatedTokenAccount(conn, operator, mint, receiverPk)).address;
  if (!MINT_IN) await spl.mintTo(conn, operator, mint, opAta, operator, 1000_000000n);

  // Fail fast and legibly rather than mid-flow, and make the wrong-reason risk explicit.
  const bal = BigInt((await conn.getTokenAccountBalance(opAta)).value.amount);
  console.log(`operator token balance: ${human(bal)}  (cap ${human(CAP)}, within ${human(WITHIN)}, over ${human(OVER)})`);
  if (bal < WITHIN + OVER) {
    console.error(`FATAL: balance ${human(bal)} < within+over ${human(WITHIN + OVER)}.`);
    console.error('       The over-cap attempt could then be refused for insufficient funds rather');
    console.error('       than by the cap, which would not prove what this harness claims.');
    process.exit(1);
  }
  if (OVER <= CAP) { console.error('FATAL: E2E_OVER must exceed E2E_CAP'); process.exit(1); }

  const [subAuth] = web3.PublicKey.findProgramAddressSync(
    [enc.encode('SubscriptionAuthority'), operator.publicKey.toBuffer(), mint.toBuffer()], SF);
  const [eventAuthority] = web3.PublicKey.findProgramAddressSync([enc.encode('event_authority')], SF);

  // initSubscriptionAuthority (disc 0). Idempotent across runs on a mint we do not own.
  if (!(await conn.getAccountInfo(subAuth))) {
    await web3.sendAndConfirmTransaction(conn, new web3.Transaction().add(new web3.TransactionInstruction({
      programId: SF, data: Buffer.from([0]), keys: [
        { pubkey: operator.publicKey, isSigner: true, isWritable: true },
        { pubkey: subAuth, isSigner: false, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: opAta, isSigner: false, isWritable: true },
        { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: spl.TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: operator.publicKey, isSigner: true, isWritable: true }] })), [operator]);
  } else {
    console.log('subscription authority already exists, reusing');
  }
  const initId = (await conn.getAccountInfo(subAuth)).data.readBigInt64LE(98);

  // createFixedDelegation (disc 1). A fresh nonce per run keeps the PDA unique.
  const nonce = BigInt(process.env.E2E_NONCE || Math.floor(Math.random() * 2 ** 40));
  const [delegationPda] = web3.PublicKey.findProgramAddressSync(
    [enc.encode('delegation'), subAuth.toBuffer(), operator.publicKey.toBuffer(), delegatee.publicKey.toBuffer(), u64le(nonce)], SF);
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 86400 * 30);
  const createSig = await web3.sendAndConfirmTransaction(conn, new web3.Transaction().add(new web3.TransactionInstruction({
    programId: SF, data: Buffer.concat([Buffer.from([1]), u64le(nonce), u64le(CAP), i64le(expiry), i64le(initId)]), keys: [
      { pubkey: operator.publicKey, isSigner: true, isWritable: true },
      { pubkey: subAuth, isSigner: false, isWritable: false },
      { pubkey: delegationPda, isSigner: false, isWritable: true },
      { pubkey: delegatee.publicKey, isSigner: false, isWritable: false },
      { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: operator.publicKey, isSigner: true, isWritable: true }] })), [operator]);
  console.log(`createFixedDelegation (cap ${human(CAP)}, nonce ${nonce}):`, createSig);

  const transferIx = amount => new web3.TransactionInstruction({
    programId: SF, data: Buffer.concat([Buffer.from([4]), u64le(amount), operator.publicKey.toBuffer(), mint.toBuffer()]), keys: [
      { pubkey: delegationPda, isSigner: false, isWritable: true },
      { pubkey: subAuth, isSigner: false, isWritable: false },
      { pubkey: opAta, isSigner: false, isWritable: true },
      { pubkey: rxAta, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: spl.TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: delegatee.publicKey, isSigner: true, isWritable: false },
      { pubkey: eventAuthority, isSigner: false, isWritable: false },
      { pubkey: SF, isSigner: false, isWritable: false }] });

  const withinSig = await web3.sendAndConfirmTransaction(conn, new web3.Transaction().add(transferIx(WITHIN)), [operator, delegatee]);
  console.log(`WITHIN cap (${human(WITHIN)}) SUCCESS:`, withinSig);

  // Land the over-cap spend as a FAILED tx (skipPreflight) so the rejection is clickable.
  const tx = new web3.Transaction().add(transferIx(OVER));
  tx.feePayer = operator.publicKey; tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash; tx.sign(operator, delegatee);
  const overSig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: true });
  let tt = null;
  for (let i = 0; i < 20 && !tt; i++) {
    await new Promise(r => setTimeout(r, 3000));
    tt = await conn.getTransaction(overSig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  }
  if (!tt) { console.error('FATAL: over-cap tx never confirmed:', overSig); process.exit(1); }

  // ASSERT the rejection is the CAP, not something else. A proof that does not check WHY it
  // failed is not a proof.
  const err = tt.meta && tt.meta.err;
  const custom = err && err.InstructionError && err.InstructionError[1] && err.InstructionError[1].Custom;
  if (custom !== CAP_ERROR) {
    console.error(`FATAL: expected custom error ${CAP_ERROR} (0x12c, over-cap), got ${JSON.stringify(err)}`);
    console.error('       The transaction failed for the WRONG REASON, so this is not evidence the');
    console.error('       cap was enforced. Do not publish this run.');
    if (tt.meta && tt.meta.logMessages) tt.meta.logMessages.slice(-8).forEach(l => console.error('  ', l));
    process.exit(1);
  }
  console.log(`OVER cap (${human(OVER)}) REJECTED on-chain, custom error ${custom} (0x12c):`, overSig);

  console.log(`\nexplorer (${CLUSTER}):`);
  console.log('  create :', explorer(createSig));
  console.log('  within :', explorer(withinSig));
  console.log('  over   :', explorer(overSig));
  console.log('\nVERDICT: cap enforced by the audited program, verified by error code.');
}
main().catch(e => { console.error('FATAL:', e.message || e); if (e.logs) e.logs.slice(-6).forEach(l => console.error(' ', l)); process.exit(1); });
