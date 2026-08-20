//! A bounded subset of npm's `minimatch` syntax for workspace paths.
//!
//! The parser deliberately has no filesystem behavior. It compiles one
//! normalized, positive workspace pattern and matches normalized package-map
//! keys. Negation ordering and path separator normalization remain the
//! caller's responsibility.
//!
//! npm's common workspace syntax is supported, including its suffix-aware
//! extglob behavior. Negative extglobs use a component-bound lookahead that
//! includes the remainder after every enclosing extglob. Plain `*` chunks keep
//! npm's non-empty adjacency rule instead of being collapsed with `**`.
//! Extglob alternatives containing `/` remain unsupported and are rejected
//! rather than broadened across path components.
//! Backslash escaping is intentionally unavailable because the caller first
//! normalizes npm's Windows-style separators to `/`. Numeric and ASCII-letter
//! brace ranges are expanded with the same result bound as comma braces.

use std::collections::HashSet;
use unicode_general_category::{GeneralCategory, get_general_category};

pub(crate) const MAX_WORKSPACE_PATTERNS: usize = 256;

const MAX_PATTERN_BYTES: usize = 1_024;
const MAX_CANDIDATE_BYTES: usize = 4_096;
const MAX_COMPONENTS: usize = 256;
const MAX_BRACE_EXPANSIONS: usize = 256;
const MAX_AST_NODES: usize = 4_096;
const MAX_NESTING: usize = 32;
const MAX_MATCH_WORK: usize = 250_000;

#[derive(Debug, Clone)]
pub(crate) struct NpmMinimatch {
    alternatives: Vec<PathPattern>,
    comment: bool,
}

#[derive(Debug, Clone)]
struct PathPattern {
    components: Vec<PathComponent>,
}

#[derive(Debug, Clone)]
enum PathComponent {
    GlobStar,
    Pattern {
        sequence: Sequence,
        unit_mode: UnitMode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitMode {
    Utf16,
    UnicodeScalar,
}

#[derive(Debug, Clone, Copy)]
struct MatchInput<'a> {
    units: &'a [u32],
    ceiling: usize,
    unit_mode: UnitMode,
}

#[derive(Debug, Clone)]
struct Sequence {
    tokens: Vec<Token>,
    at_component_start: bool,
}

#[derive(Debug, Clone)]
enum Token {
    Literal(char),
    LiteralText(String),
    AnyChar,
    Star {
        sole_in_part: bool,
        allow_empty: bool,
    },
    Class(CharacterClass),
    Extglob {
        kind: ExtglobKind,
        alternatives: Vec<Sequence>,
        at_component_start: bool,
        /// npm 11's bundled minimatch lowers a trailing-empty negative extglob,
        /// or one whose final alternative ends in another extglob, to a
        /// non-empty component wildcard. Keep that compatibility quirk explicit.
        negative_non_empty_wildcard: bool,
        /// `fillNegs` clones suffix ASTs without copying minimatch's empty-ext
        /// marker. The clone must therefore retain its negative lookahead even
        /// when the original suffix occurrence broadens to a wildcard.
        copied_into_negative_suffix: bool,
        original: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtglobKind {
    ExactlyOne,
    ZeroOrOne,
    OneOrMore,
    ZeroOrMore,
    Negated,
}

#[derive(Debug, Clone)]
struct CharacterClass {
    negated: bool,
    unicode_items: Vec<ClassItem>,
    utf16_items: Vec<ClassItem>,
}

#[derive(Debug, Clone)]
enum ClassItem {
    Character(u32),
    Range(u32, u32),
    Posix(PosixClass),
}

#[derive(Debug, Clone, Copy)]
enum PosixClass {
    Alnum,
    Alpha,
    Ascii,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Word,
    Xdigit,
}

impl NpmMinimatch {
    /// Compiles one positive pattern. A leading `#` follows npm minimatch's
    /// default comment behavior and produces a matcher that never matches.
    pub(crate) fn compile(pattern: &str) -> Result<Self, String> {
        validate_pattern_text(pattern)?;
        if pattern.starts_with('#') {
            return Ok(Self {
                alternatives: Vec::new(),
                comment: true,
            });
        }

        let expanded = expand_braces(pattern)?;
        let mut alternatives = Vec::with_capacity(expanded.len());
        let mut node_count = 0usize;
        for expansion in expanded {
            let normalized = normalize_repeated_slashes(&expansion);
            if normalized.split('/').any(str::is_empty) {
                // Brace expansion can produce a trailing separator (for
                // example `packages/{,a}`). Package-map keys never contain an
                // empty component, so that alternative is impossible while
                // its siblings remain valid.
                continue;
            }
            alternatives.push(parse_path_pattern(&normalized, &mut node_count)?);
        }

        Ok(Self {
            alternatives,
            comment: false,
        })
    }

    /// Tests a normalized package-map key. Runtime work is capped; exceeding
    /// the cap is an error rather than a permissive match.
    pub(crate) fn is_match(&self, candidate: &str) -> Result<bool, String> {
        if self.comment {
            return Ok(false);
        }
        validate_candidate(candidate)?;
        let candidate_components = candidate.split('/').collect::<Vec<_>>();
        let mut context = MatchContext::default();
        for alternative in &self.alternatives {
            if alternative.is_match(&candidate_components, &mut context)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

mod braces;
mod character_class;
mod component;
mod lowering;
mod matching;
mod path;
mod pattern;

use braces::*;
use character_class::*;
use component::*;
use lowering::*;
use matching::*;
use pattern::*;

#[cfg(test)]
mod tests;
