//! Bakes this binary's own build provenance in at compile time.
//!
//! WHY THE PROCESS HAS TO ANSWER THIS ABOUT ITSELF. `/selfcheck` already
//! publishes `deployed_sha`, and that field is correct: it names the commit the
//! WORKSPACE deploy was generated from, the config and skills and SOPs listed in
//! `deploy/deploy-targets.json`. This binary is a compiled artifact that is
//! deliberately not in that map, for the same reason the nine plugins are not.
//! So `deployed_sha` says nothing at all about the code that is answering the
//! request, and nothing else on the box could either. The two answer different
//! questions and the second one simply did not exist.
//!
//! The gap was not theoretical. On 2026-08-17 the live gate served a
//! `deployed_sha` three commits behind the source it had been built from, while
//! its own deploy-vintage line reported agreement. Every value published was
//! true. The one that would have shown the difference was missing.
//!
//! A build date cannot substitute, which is the trap this replaces rather than
//! repeats: a rebuild of an old checkout is new-dated and old-versioned, so a
//! file's mtime answers when someone typed `cargo build` and never what they
//! built. Ask the artifact what it IS.
//!
//! THREE SOURCES, IN ORDER, and the emitted `_SOURCE` value always says which
//! one was used so a reader never has to infer it:
//!
//!   `env`         `X402_GATE_BUILD_COMMIT` was set at build time. This is the
//!                 route for a build with no repository attached: a source
//!                 tarball, a distro package, a Docker build over a copied tree.
//!                 It is taken verbatim, so it is a statement by whoever built
//!                 rather than an observation, and the source label is what makes
//!                 that distinction legible instead of hidden.
//!   `git`         read from the repository, tree clean.
//!   `git-dirty`   read from the repository, tree NOT clean. The commit then
//!                 carries a `-dirty` suffix, because a dirty tree's HEAD does
//!                 not name the code that was compiled and a bare sha there would
//!                 read as if it did. The suffix means an equality check against
//!                 a real commit cannot quietly pass.
//!   `unavailable` no git, no repository, no override. The commit is the literal
//!                 string `unknown`.
//!
//! NEVER AN EMPTY STRING. An absent value that serialises as `""` reads as
//! present-and-fine to a consumer and as absent to a human, which is the worst of
//! both; `unknown` is neither hex nor 40 characters, so it cannot be mistaken for
//! a commit by either.
//!
//! A MISSING GIT IS NOT A BUILD FAILURE. Every git call here is allowed to fail
//! and falls back down the ladder. A provenance field is worth having and is not
//! worth refusing to compile over.

use std::process::Command;

fn main() {
    let (commit, source) = provenance();
    println!("cargo:rustc-env=X402_GATE_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=X402_GATE_BUILD_COMMIT_SOURCE={source}");

    // The override is read at build time, so cargo has to know the build script
    // depends on it or a forced value would stick across a later unforced build.
    println!("cargo:rerun-if-env-changed=X402_GATE_BUILD_COMMIT");

    for path in watch_paths() {
        println!("cargo:rerun-if-changed={path}");
    }
}

/// The commit and the label naming where it came from.
fn provenance() -> (String, String) {
    if let Ok(forced) = std::env::var("X402_GATE_BUILD_COMMIT") {
        let forced = sanitize(&forced);
        if !forced.is_empty() {
            return (forced, "env".to_string());
        }
    }

    let head = match git(&["rev-parse", "HEAD"]) {
        Some(h) if !h.is_empty() => h,
        // No repository, no git binary, or an unborn HEAD. All three mean the
        // same thing to a reader of the response: this build cannot say.
        _ => return ("unknown".to_string(), "unavailable".to_string()),
    };

    // `--porcelain` prints one line per changed path and nothing whatsoever for a
    // clean tree, so emptiness is the signal and no parsing is involved.
    //
    // UNTRACKED FILES COUNT AS DIRTY, which is the conservative direction rather
    // than an oversight. An untracked file that some module references is
    // compiled into this binary exactly like a tracked one, and the commit does
    // not contain it. Erring the other way would let real divergence report clean.
    //
    // A git that answered `rev-parse` and then failed here is treated as dirty
    // too: the honest answer to "is this tree clean" that we could not obtain is
    // not "yes".
    let dirty = match git(&["status", "--porcelain"]) {
        Some(out) => !out.is_empty(),
        None => true,
    };

    if dirty {
        (format!("{head}-dirty"), "git-dirty".to_string())
    } else {
        (head, "git".to_string())
    }
}

/// Run git in the crate's own directory and return trimmed stdout, or `None` for
/// anything that did not cleanly succeed.
///
/// `current_dir` is the manifest directory rather than the process cwd, because
/// cargo can be invoked from anywhere and a git command that resolved against the
/// caller's cwd would describe whatever repository they happened to be standing
/// in.
fn git(args: &[&str]) -> Option<String> {
    let dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(sanitize(&String::from_utf8_lossy(&out.stdout)))
}

/// First line, no control characters, bounded length.
///
/// A `cargo:rustc-env` directive is LINE-BASED, so an embedded newline does not
/// error: it silently truncates the value and feeds the remainder to cargo as
/// another directive. Taking the first line rather than stripping newlines
/// matters for the same reason. Joining `a\nb` into `ab` would invent a value
/// that was never anywhere, where the first line is at least a real one.
///
/// The length bound exists because the override is arbitrary text from the build
/// environment and this value is served in a public HTTP response. 64 leaves room
/// for a 40-character sha plus the `-dirty` suffix.
fn sanitize(raw: &str) -> String {
    raw.lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}

/// The paths whose change must re-run this script.
///
/// Emitting any `rerun-if-changed` replaces cargo's default of watching the whole
/// package, so the package's own sources are listed back explicitly. Missing them
/// would mean an ordinary edit rebuilt the crate while the build script kept its
/// previous answer.
///
/// `--git-path` rather than a literal `.git/...`: inside a worktree, `.git` is a
/// FILE holding a `gitdir:` pointer and the real HEAD lives under
/// `.git/worktrees/<name>/`. Asking git resolves that; guessing does not.
///
/// HONEST LIMIT. This catches every way the COMMIT can move (a commit, an amend,
/// a checkout, a branch switch all rewrite HEAD or the ref it names) and every
/// edit inside this crate. It does not catch a tree that became dirty somewhere
/// ELSE in the repository while this crate and HEAD both stood still, so the
/// `-dirty` flag is best effort where the commit is not. The direction of that
/// error is worth stating plainly: such a build can report clean while the
/// repository was not.
fn watch_paths() -> Vec<String> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let mut paths = vec![
        format!("{manifest}/src"),
        format!("{manifest}/Cargo.toml"),
        format!("{manifest}/build.rs"),
    ];

    if let Some(head_path) = git(&["rev-parse", "--git-path", "HEAD"]) {
        // A symbolic HEAD names a ref file that the sha actually lives in, and
        // committing rewrites that file rather than HEAD. Watching only HEAD
        // would therefore miss the single most common way the commit moves.
        if let Ok(content) = std::fs::read_to_string(&head_path) {
            if let Some(name) = content.trim().strip_prefix("ref: ") {
                if let Some(ref_path) = git(&["rev-parse", "--git-path", name]) {
                    paths.push(ref_path);
                }
            }
        }
        paths.push(head_path);
    }

    // Only when it exists. Cargo re-runs a build script unconditionally while any
    // watched path is missing, and a repository with no packed-refs is ordinary,
    // so listing it blind would quietly make every build re-run this script.
    if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        if std::path::Path::new(&packed).exists() {
            paths.push(packed);
        }
    }

    paths
}
