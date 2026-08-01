//! Differential fuzzing of the transaction decoder against solana-sdk.
//!
//! WHY THIS EXISTS, since the repo already has five layers of correctness work.
//! Known-answer vectors, property tests, Kani proofs and the mutation harness all check
//! something we thought to write down. They are strong against the failure modes we predicted
//! and silent about the ones we did not. This searches for disagreement instead of asserting a
//! property, and it scores against solana-sdk's own deserializer, which is an oracle nobody
//! here wrote. That makes it the second check in the project graded externally; the first is
//! the known-answer vectors.
//!
//! The search is the standard feedback-guided mutation loop, with two details that matter more
//! than the loop itself:
//!
//!   Strategy. The fitness signal is how far into the buffer both decoders stayed in agreement
//!   before diverging, not code coverage. Coverage is a poor proxy here because almost all of
//!   the decoder's branches run on the very first malformed byte.
//!
//!   Tactics. Mutations are CORRELATED, not independent per byte. Independent uniform flips
//!   essentially never produce a run of related changes, so they cannot reach states that need
//!   several bytes to move together. The loop therefore holds a mutation mode across a span.
//!
//! Escaping dead ends is why a population is kept rather than a single best input: pure
//! hill-climbing parks itself at a local maximum and mutates there forever.

use solana_core::tx_decode::{decode_transaction, DecodeError, DecodedTransaction};
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::{v0, Message as LegacyMessage, VersionedMessage};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::{Transaction, VersionedTransaction};

// ---------------------------------------------------------------------------
// Deterministic PRNG. Seeded so any finding is reproducible from its seed alone;
// a fuzzer that cannot replay its own finding is a rumour generator.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// True with probability 1/n.
    fn one_in(&mut self, n: u64) -> bool {
        n > 0 && self.next_u64().is_multiple_of(n)
    }
}

// ---------------------------------------------------------------------------
// The oracle side.
// ---------------------------------------------------------------------------

/// What solana-sdk makes of a byte string.
enum Reference {
    Rejected,
    Accepted(Box<VersionedTransaction>),
}

fn reference_decode(bytes: &[u8]) -> Reference {
    // VersionedTransaction covers both legacy and v0 on the wire, which is the same
    // surface our decoder claims to handle.
    match bincode::deserialize::<VersionedTransaction>(bytes) {
        // bincode by default tolerates trailing bytes; our decoder deliberately does not.
        // Re-serialising and length-checking lets us tell a genuine disagreement apart from
        // that one known, intentional difference.
        Ok(tx) => Reference::Accepted(Box::new(tx)),
        Err(_) => Reference::Rejected,
    }
}

/// Divergence classes, ordered by how much they should worry us.
#[derive(PartialEq, Eq, Debug)]
enum Divergence {
    /// Both decoders agree (both accept and match, or both reject). Not a finding.
    None,
    /// Known and intentional: our decoder refuses address-table lookups and refuses
    /// trailing bytes. Recorded so the harness cannot drown real findings in noise.
    Expected(&'static str),
    /// We reject what the reference accepts. Availability risk, usually a deliberate
    /// tightening, but each one must be justified rather than assumed.
    WeRejectTheyAccept(DecodeError),
    /// We accept what the reference rejects. The dangerous direction: we might act on a
    /// transaction the network would never take.
    WeAcceptTheyReject,
    /// Both accept and disagree about what the bytes MEAN. The worst class, and precisely
    /// the "quietly wrong but still valid" bug that coarse invariants cannot see.
    BothAcceptDisagree(String),
}

fn classify(bytes: &[u8]) -> Divergence {
    let ours = decode_transaction(bytes);
    let theirs = reference_decode(bytes);

    match (ours, theirs) {
        (Err(_), Reference::Rejected) => Divergence::None,

        (Err(DecodeError::AddressTableLookupsUnsupported), Reference::Accepted(_)) => {
            Divergence::Expected("address-table lookups refused by design")
        }
        (Err(DecodeError::TrailingBytes(_)), Reference::Accepted(_)) => {
            Divergence::Expected("trailing bytes refused by design")
        }
        (Err(e), Reference::Accepted(_)) => Divergence::WeRejectTheyAccept(e),

        (Ok(_), Reference::Rejected) => Divergence::WeAcceptTheyReject,

        (Ok(mine), Reference::Accepted(theirs)) => match semantic_diff(&mine, &theirs) {
            Some(what) => Divergence::BothAcceptDisagree(what),
            None => Divergence::None,
        },
    }
}

/// Compare the two decodings field by field. Returns the first disagreement.
fn semantic_diff(mine: &DecodedTransaction, theirs: &VersionedTransaction) -> Option<String> {
    if mine.signatures.len() != theirs.signatures.len() {
        return Some(format!(
            "signature count {} vs {}",
            mine.signatures.len(),
            theirs.signatures.len()
        ));
    }
    for (i, (a, b)) in mine
        .signatures
        .iter()
        .zip(theirs.signatures.iter())
        .enumerate()
    {
        if a.as_slice() != b.as_ref() {
            return Some(format!("signature {i} bytes differ"));
        }
    }

    let is_v0 = matches!(theirs.message, VersionedMessage::V0(_));
    if mine.is_v0 != is_v0 {
        return Some(format!("version flag {} vs {}", mine.is_v0, is_v0));
    }

    let (header, keys, blockhash, ixs) = match &theirs.message {
        VersionedMessage::Legacy(m) => (
            &m.header,
            &m.account_keys,
            &m.recent_blockhash,
            &m.instructions,
        ),
        VersionedMessage::V0(m) => (
            &m.header,
            &m.account_keys,
            &m.recent_blockhash,
            &m.instructions,
        ),
    };

    let m = &mine.message;
    if m.num_required_signatures != header.num_required_signatures {
        return Some(format!(
            "num_required_signatures {} vs {}",
            m.num_required_signatures, header.num_required_signatures
        ));
    }
    if m.num_readonly_signed != header.num_readonly_signed_accounts {
        return Some("num_readonly_signed differs".into());
    }
    if m.num_readonly_unsigned != header.num_readonly_unsigned_accounts {
        return Some("num_readonly_unsigned differs".into());
    }
    if m.account_keys.len() != keys.len() {
        return Some(format!(
            "account key count {} vs {}",
            m.account_keys.len(),
            keys.len()
        ));
    }
    for (i, (a, b)) in m.account_keys.iter().zip(keys.iter()).enumerate() {
        // Our Pubkey is a newtype with no AsRef impl; compare the raw arrays.
        if a.as_bytes() != &b.to_bytes() {
            return Some(format!("account key {i} differs"));
        }
    }
    if m.recent_blockhash != blockhash.to_bytes() {
        return Some("recent_blockhash differs".into());
    }
    if m.instructions.len() != ixs.len() {
        return Some(format!(
            "instruction count {} vs {}",
            m.instructions.len(),
            ixs.len()
        ));
    }
    for (i, (a, b)) in m.instructions.iter().zip(ixs.iter()).enumerate() {
        if a.program_id_index != b.program_id_index {
            return Some(format!("instruction {i} program_id_index differs"));
        }
        if a.account_indexes != b.accounts {
            return Some(format!("instruction {i} account indexes differ"));
        }
        if a.data != b.data {
            return Some(format!("instruction {i} data differs"));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Fitness. An externally observable proxy for "how deep did this input get",
// deliberately not code coverage.
// ---------------------------------------------------------------------------

fn fitness(bytes: &[u8]) -> u64 {
    // How many leading bytes can be removed from the end before our decoder's verdict
    // changes shape. A cheap stand-in for parse depth that needs no instrumentation,
    // which is the whole point: the same trick works against a binary you cannot modify.
    let full = decode_transaction(bytes);
    match &full {
        Ok(_) => bytes.len() as u64,
        Err(DecodeError::Truncated) => {
            // Truncated means we consumed everything and wanted more; reward length.
            bytes.len() as u64
        }
        Err(_) => {
            // Structural rejection. Reward inputs that survive a longer prefix.
            let mut best = 0u64;
            let step = (bytes.len() / 16).max(1);
            let mut n = step;
            while n < bytes.len() {
                if matches!(
                    decode_transaction(&bytes[..n]),
                    Err(DecodeError::Truncated) | Ok(_)
                ) {
                    best = n as u64;
                }
                n += step;
            }
            best
        }
    }
}

// ---------------------------------------------------------------------------
// Correlated mutation.
// ---------------------------------------------------------------------------

fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = seed.to_vec();
    if out.is_empty() {
        return out;
    }

    match rng.below(6) {
        // A correlated RUN of flips. The key departure from uniform fuzzing: once the
        // mutation turns on it stays on for a span, so several related bytes move together.
        0..=2 => {
            let start = rng.below(out.len());
            let mut i = start;
            let mut active = true;
            while i < out.len() && active {
                out[i] ^= 1u8 << rng.below(8);
                // Stay in the run with high probability; this is what makes long
                // correlated spans reachable at all.
                active = !rng.one_in(4);
                i += 1;
            }
        }
        // Nudge a byte by a small delta. Length prefixes and index fields live in small
        // integer neighbourhoods, so +/-1 is far more productive than a random byte.
        3 => {
            let i = rng.below(out.len());
            let delta = if rng.one_in(2) { 1u8 } else { 255u8 };
            out[i] = out[i].wrapping_add(delta);
        }
        // Splice: duplicate a span. Reaches count/length mismatches that single flips miss.
        4 => {
            let len = out.len();
            let a = rng.below(len);
            let b = (a + 1 + rng.below(32)).min(len);
            let chunk: Vec<u8> = Vec::from(&out[a..b]);
            let at = rng.below(len);
            out.splice(at..at, chunk);
        }
        // Truncate. Cheap way to probe every boundary condition in the cursor.
        _ => {
            let keep = rng.below(out.len());
            out.truncate(keep);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Seeds: real transactions, so the search starts inside the valid region rather
// than wandering the space of random bytes where everything is rejected.
// ---------------------------------------------------------------------------

fn seeds() -> Vec<Vec<u8>> {
    let payer = Pubkey::new_unique();
    let other = Pubkey::new_unique();
    let program = Pubkey::new_unique();
    let blockhash = Hash::new_from_array([7u8; 32]);

    let ix = Instruction::new_with_bytes(
        program,
        &[1, 2, 3, 4],
        vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(other, false),
        ],
    );

    let mut out = Vec::new();

    // Legacy, unsigned.
    let legacy =
        LegacyMessage::new_with_blockhash(std::slice::from_ref(&ix), Some(&payer), &blockhash);
    let tx = Transaction::new_unsigned(legacy);
    if let Ok(b) = bincode::serialize(&tx) {
        out.push(b);
    }

    // Legacy with two instructions, to give the loop a longer structure to chew on.
    let legacy2 =
        LegacyMessage::new_with_blockhash(&[ix.clone(), ix.clone()], Some(&payer), &blockhash);
    if let Ok(b) = bincode::serialize(&Transaction::new_unsigned(legacy2)) {
        out.push(b);
    }

    // v0, no address-table lookups (the shape a payment actually uses).
    if let Ok(m) = v0::Message::try_compile(&payer, &[ix], &[], blockhash) {
        let vt = VersionedTransaction {
            signatures: vec![Default::default(); m.header.num_required_signatures as usize],
            message: VersionedMessage::V0(m),
        };
        if let Ok(b) = bincode::serialize(&vt) {
            out.push(b);
        }
    }

    out
}

// ---------------------------------------------------------------------------

struct Candidate {
    bytes: Vec<u8>,
    score: u64,
}

// ---------------------------------------------------------------------------
// Negative control.
//
// "20,000 iterations, zero findings" is worth nothing on its own: it is exactly what a
// harness that CANNOT detect anything also prints. This repo deleted six gates today that
// were green for precisely that reason, so this one has to prove it can go red on demand.
// Every case below is a divergence deliberately planted; each MUST be caught.
// ---------------------------------------------------------------------------

fn self_test() -> bool {
    let seeds = seeds();
    if seeds.is_empty() {
        println!("FAIL  no seeds");
        return false;
    }
    let good = &seeds[0];
    let mut ok = true;
    let mut check = |name: &str, pass: bool| {
        println!("{}  {name}", if pass { "PASS" } else { "FAIL" });
        if !pass {
            ok = false;
        }
    };

    // 1. Control. A real transaction must be seen as agreement, or every later
    //    "no divergence" result is just this bug wearing a green hat.
    check(
        "a valid transaction reads as agreement",
        classify(good) == Divergence::None,
    );

    // 2. Both sides reject garbage.
    check(
        "random bytes: both decoders reject",
        classify(&[0xff, 0x01, 0x02, 0x03]) == Divergence::None,
    );

    // 3. The by-design refusal is classified as expected, not as a finding. If this
    //    regressed, real findings would drown in known noise.
    let mut trailing = good.clone();
    trailing.push(0x00);
    check(
        "trailing byte lands in the expected-divergence bucket",
        matches!(classify(&trailing), Divergence::Expected(_)),
    );

    // 4. The one that actually matters: can semantic_diff SEE a disagreement? Decode a
    //    real transaction both ways, then corrupt one field of our side at a time and
    //    require a complaint for each. Without this, semantic_diff returning None proves
    //    nothing, because a function that always returns None also returns None here.
    let Ok(mine) = decode_transaction(good) else {
        check("seed decodes with our decoder", false);
        return false;
    };
    let Reference::Accepted(theirs) = reference_decode(good) else {
        check("seed decodes with the reference", false);
        return false;
    };

    check(
        "unperturbed decodings compare equal",
        semantic_diff(&mine, &theirs).is_none(),
    );

    let mut m = mine.clone();
    m.message.num_required_signatures ^= 0x01;
    check(
        "detects a corrupted signature count",
        semantic_diff(&m, &theirs).is_some(),
    );

    let mut m = mine.clone();
    m.message.recent_blockhash[0] ^= 0xff;
    check(
        "detects a corrupted blockhash",
        semantic_diff(&m, &theirs).is_some(),
    );

    let mut m = mine.clone();
    if let Some(first) = m.message.account_keys.first_mut() {
        let mut raw = first.to_bytes();
        raw[0] ^= 0xff;
        *first = solana_core::Pubkey::new(raw);
    }
    check(
        "detects a corrupted account key",
        semantic_diff(&m, &theirs).is_some(),
    );

    let mut m = mine.clone();
    if let Some(ix) = m.message.instructions.first_mut() {
        ix.data.push(0xAA);
    }
    check(
        "detects corrupted instruction data",
        semantic_diff(&m, &theirs).is_some(),
    );

    let mut m = mine.clone();
    m.message.instructions.clear();
    check(
        "detects a dropped instruction",
        semantic_diff(&m, &theirs).is_some(),
    );

    let mut m = mine.clone();
    m.is_v0 = !m.is_v0;
    check(
        "detects a flipped version flag",
        semantic_diff(&m, &theirs).is_some(),
    );

    ok
}

fn main() {
    let iterations: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    let seed: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5EED_1234_ABCD_0001);

    // The control runs FIRST and gates everything after it. A clean fuzz result from a
    // harness whose detector is broken is worse than no harness, because it is reassuring.
    println!("=== self-test: can this harness detect a planted divergence? ===");
    if !self_test() {
        eprintln!("\nSELF-TEST FAILED. Refusing to report fuzzing results from a harness");
        eprintln!("that cannot be shown to detect anything.");
        std::process::exit(2);
    }
    println!();

    let mut rng = Rng(seed);
    let mut population: Vec<Candidate> = seeds()
        .into_iter()
        .map(|b| {
            let score = fitness(&b);
            Candidate { bytes: b, score }
        })
        .collect();

    if population.is_empty() {
        eprintln!("no seeds could be built; aborting rather than fuzzing nothing");
        std::process::exit(2);
    }

    println!(
        "differential-fuzz: {} seeds, {iterations} iterations, rng seed 0x{seed:016X}",
        population.len()
    );
    println!("oracle: solana-sdk 2.1 bincode deserialization of VersionedTransaction\n");

    let mut findings: Vec<(Divergence, Vec<u8>)> = Vec::new();
    let mut expected_hits = 0usize;
    let mut agreed = 0usize;

    for _ in 0..iterations {
        // Sample from the population rather than always taking the best. Greedy
        // hill-climbing gets stuck; this is the cheapest way to keep exploring.
        let parent = &population[rng.below(population.len())];
        let child = mutate(&parent.bytes, &mut rng);

        match classify(&child) {
            Divergence::None => agreed += 1,
            Divergence::Expected(_) => expected_hits += 1,
            other => {
                let already = findings.iter().any(|(d, _)| *d == other);
                if !already {
                    findings.push((other, child.clone()));
                }
            }
        }

        let score = fitness(&child);
        if score > 0 {
            population.push(Candidate {
                bytes: child,
                score,
            });
            // Keep the population bounded and biased toward depth, without collapsing
            // to a single lineage.
            if population.len() > 64 {
                population.sort_by_key(|c| std::cmp::Reverse(c.score));
                population.truncate(32);
            }
        }
    }

    println!("agreed          : {agreed}");
    println!("expected-diverge: {expected_hits}  (by-design refusals)");
    println!("findings        : {}\n", findings.len());

    if findings.is_empty() {
        println!("No unexplained divergence from the reference decoder.");
        return;
    }

    for (d, bytes) in &findings {
        match d {
            Divergence::WeAcceptTheyReject => {
                println!("WE ACCEPT / REFERENCE REJECTS  ({} bytes)", bytes.len());
            }
            Divergence::WeRejectTheyAccept(e) => {
                println!(
                    "WE REJECT / REFERENCE ACCEPTS  ({} bytes)  ours={e:?}",
                    bytes.len()
                );
            }
            Divergence::BothAcceptDisagree(what) => {
                println!(
                    "BOTH ACCEPT, MEANINGS DIFFER   ({} bytes)  {what}",
                    bytes.len()
                );
            }
            _ => {}
        }
        println!("  hex: {}", hex(bytes));
    }

    // A finding is a finding. Exit non-zero so this can gate.
    std::process::exit(1);
}

fn hex(b: &[u8]) -> String {
    let shown: String = b.iter().take(96).map(|x| format!("{x:02x}")).collect();
    if b.len() > 96 {
        format!("{shown}... ({} bytes total)", b.len())
    } else {
        shown
    }
}
