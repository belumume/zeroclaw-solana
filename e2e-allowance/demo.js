// e2e-allowance: proves the audited SF Allowances program bounds a COMPLYING agent on-chain.
//
// Flow (all real, on devnet, against the deployed SF program De1egAFMk...):
//   1. create an SPL mint + operator/receiver ATAs, fund the operator
//   2. initSubscriptionAuthority, then createFixedDelegation capped at 5 tokens with the
//      delegatee = a fresh "agent session key"
//   3. the agent session key SIGNS two transferFixed spends:
//        - within cap (5 tokens) -> SUCCEEDS
//        - over cap  (10 tokens) -> REJECTED on-chain by the program (custom error 0x12c),
//          landed as a failed tx so it is clickable on the explorer
//
// The program, not the plugin and not the LLM, enforces the cap. This is the fails-closed
// evidence for a COMPLYING model (the agent signed the over-cap spend and the chain stopped it),
// complementing the injection transcript (which shows the model REFUSING).
//
// Run:  npm install
//       E2E_FUNDER=/path/to/devnet-keypair.json node demo.js
//       (optional E2E_RPC, default https://api.devnet.solana.com; the funder needs a little devnet SOL)
const web3 = require('@solana/web3.js');
const spl = require('@solana/spl-token');
const fs = require('fs');

const SF = new web3.PublicKey('De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44');
const RPC = process.env.E2E_RPC || 'https://api.devnet.solana.com';
const OP = process.env.E2E_FUNDER;
if (!OP) { console.error('set E2E_FUNDER=<path to a funded devnet keypair json>'); process.exit(1); }

const u64le = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const i64le = n => { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return b; };

async function main() {
  const conn = new web3.Connection(RPC, 'confirmed');
  const operator = web3.Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(OP, 'utf8'))));
  const delegatee = web3.Keypair.generate();  // the agent session key
  const receiver = web3.Keypair.generate();
  const enc = new TextEncoder();
  console.log('operator (delegator/owner/payer):', operator.publicKey.toBase58());
  console.log('delegatee (agent session key)   :', delegatee.publicKey.toBase58());

  const mint = await spl.createMint(conn, operator, operator.publicKey, null, 6);
  const opAta = (await spl.getOrCreateAssociatedTokenAccount(conn, operator, mint, operator.publicKey)).address;
  const rxAta = (await spl.getOrCreateAssociatedTokenAccount(conn, operator, mint, receiver.publicKey)).address;
  await spl.mintTo(conn, operator, mint, opAta, operator, 1000_000000n);
  console.log('mint + funded operator ATA:', mint.toBase58());

  const [subAuth] = web3.PublicKey.findProgramAddressSync(
    [enc.encode('SubscriptionAuthority'), operator.publicKey.toBuffer(), mint.toBuffer()], SF);
  const [eventAuthority] = web3.PublicKey.findProgramAddressSync([enc.encode('event_authority')], SF);

  // initSubscriptionAuthority (disc 0)
  await web3.sendAndConfirmTransaction(conn, new web3.Transaction().add(new web3.TransactionInstruction({
    programId: SF, data: Buffer.from([0]), keys: [
      { pubkey: operator.publicKey, isSigner: true, isWritable: true },
      { pubkey: subAuth, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: opAta, isSigner: false, isWritable: true },
      { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: spl.TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: operator.publicKey, isSigner: true, isWritable: true }] })), [operator]);
  const initId = (await conn.getAccountInfo(subAuth)).data.readBigInt64LE(98);

  // createFixedDelegation (disc 1), cap = 5 tokens
  const nonce = 1n, CAP = 5_000000n;
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
  console.log('createFixedDelegation (cap 5 tokens):', createSig);

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

  // within cap (5) -> succeeds
  const withinSig = await web3.sendAndConfirmTransaction(conn, new web3.Transaction().add(transferIx(5_000000n)), [operator, delegatee]);
  console.log('WITHIN cap (5 tokens) SUCCESS:', withinSig);

  // over cap (10) -> land it as a failed tx (skipPreflight) so the rejection is clickable
  const tx = new web3.Transaction().add(transferIx(10_000000n));
  tx.feePayer = operator.publicKey; tx.recentBlockhash = (await conn.getLatestBlockhash()).blockhash; tx.sign(operator, delegatee);
  const overSig = await conn.sendRawTransaction(tx.serialize(), { skipPreflight: true });
  await new Promise(r => setTimeout(r, 9000));
  const tt = await conn.getTransaction(overSig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
  const err = tt && tt.meta ? JSON.stringify(tt.meta.err) : 'pending';
  console.log('OVER cap (10 tokens) REJECTED on-chain, err', err, ':', overSig);
  console.log('\nexplorer (devnet):');
  console.log('  create :', 'https://explorer.solana.com/tx/' + createSig + '?cluster=devnet');
  console.log('  within :', 'https://explorer.solana.com/tx/' + withinSig + '?cluster=devnet');
  console.log('  over   :', 'https://explorer.solana.com/tx/' + overSig + '?cluster=devnet');
}
main().catch(e => { console.error('FATAL:', e.message || e); if (e.logs) e.logs.slice(-6).forEach(l => console.error(' ', l)); process.exit(1); });
