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

fn normalize_repeated_slashes(pattern: &str) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    let mut previous_was_slash = false;
    for character in pattern.chars() {
        if character == '/' {
            if previous_was_slash {
                continue;
            }
            previous_was_slash = true;
        } else {
            previous_was_slash = false;
        }
        normalized.push(character);
    }
    normalized
}

fn validate_pattern_text(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("npm workspace pattern must not be empty".to_owned());
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(format!(
            "npm workspace pattern exceeds the {MAX_PATTERN_BYTES}-byte limit"
        ));
    }
    if pattern.contains('\0') {
        return Err("npm workspace pattern contains a NUL byte".to_owned());
    }
    if pattern.contains('\\') {
        return Err("npm workspace pattern must use normalized forward slashes".to_owned());
    }
    Ok(())
}

fn validate_candidate(candidate: &str) -> Result<(), String> {
    if candidate.is_empty() {
        return Err("npm workspace candidate must not be empty".to_owned());
    }
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return Err(format!(
            "npm workspace candidate exceeds the {MAX_CANDIDATE_BYTES}-byte limit"
        ));
    }
    if candidate.contains(['\0', '\\']) {
        return Err("npm workspace candidate is not a normalized package-map key".to_owned());
    }
    let mut components = 0usize;
    for component in candidate.split('/') {
        components += 1;
        if component.is_empty() || matches!(component, "." | "..") {
            return Err("npm workspace candidate contains an invalid path component".to_owned());
        }
    }
    if components > MAX_COMPONENTS {
        return Err(format!(
            "npm workspace candidate exceeds the {MAX_COMPONENTS}-component limit"
        ));
    }
    Ok(())
}

fn parse_path_pattern(pattern: &str, node_count: &mut usize) -> Result<PathPattern, String> {
    reject_cross_component_extglobs(pattern)?;
    let raw_components = pattern.split('/').collect::<Vec<_>>();
    if raw_components.len() > MAX_COMPONENTS {
        return Err(format!(
            "npm workspace pattern exceeds the {MAX_COMPONENTS}-component limit"
        ));
    }
    if raw_components
        .iter()
        .any(|component| component.is_empty() || *component == "..")
    {
        return Err("npm workspace pattern contains an invalid path component".to_owned());
    }

    let mut raw_pattern_components = Vec::with_capacity(raw_components.len());
    for component in raw_components {
        if component == "**" {
            if !matches!(raw_pattern_components.last(), Some(PathComponent::GlobStar)) {
                raw_pattern_components.push(PathComponent::GlobStar);
            }
            continue;
        }
        let mut parser = ComponentParser::new(component, node_count);
        let sequence = parser.parse_top_level()?;
        sequence.validate_empty_quantifiers()?;
        sequence.validate_repeat_clone_sensitive_empty_exact()?;
        let unit_mode = if sequence.requires_unicode_regexp() {
            UnitMode::UnicodeScalar
        } else {
            UnitMode::Utf16
        };
        if unit_mode == UnitMode::UnicodeScalar
            && sequence.contains_invalid_unicode_identity_escape()
        {
            return Err(
                "npm workspace pattern is invalid under minimatch's Unicode regular-expression rules"
                    .to_owned(),
            );
        }
        raw_pattern_components.push(PathComponent::Pattern {
            sequence,
            unit_mode,
        });
    }

    let mut components = Vec::with_capacity(raw_pattern_components.len());
    for component in raw_pattern_components {
        components.push(match component {
            PathComponent::GlobStar => PathComponent::GlobStar,
            PathComponent::Pattern {
                sequence,
                unit_mode,
            } => PathComponent::Pattern {
                sequence: lower_sequence(
                    &sequence,
                    true,
                    true,
                    true,
                    RawRemainder::empty(),
                    node_count,
                )?,
                unit_mode,
            },
        });
    }
    Ok(PathPattern { components })
}

fn reject_cross_component_extglobs(pattern: &str) -> Result<(), String> {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut extglob_depth = 0usize;
    let mut in_class = false;
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        match current {
            '[' => in_class = true,
            ']' => in_class = false,
            '@' | '?' | '+' | '*' | '!' if !in_class && chars.get(index + 1) == Some(&'(') => {
                extglob_depth += 1;
                index += 1;
            }
            ')' if !in_class && extglob_depth > 0 => extglob_depth -= 1,
            '/' if !in_class && extglob_depth > 0 => {
                return Err(
                    "npm workspace extglob alternatives must not cross path separators".to_owned(),
                );
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn mark_plain_star_parts(tokens: &mut [Token]) {
    let mut part_start = 0usize;
    for index in 0..=tokens.len() {
        let at_boundary = index == tokens.len() || matches!(tokens[index], Token::Extglob { .. });
        if !at_boundary {
            continue;
        }
        if index == part_start + 1
            && let Token::Star { sole_in_part, .. } = &mut tokens[part_start]
        {
            *sole_in_part = true;
        }
        part_start = index.saturating_add(1);
    }
}

const MAX_REMAINDER_PARTS: usize = MAX_NESTING + 1;

#[derive(Clone, Copy)]
struct RawRemainder<'a> {
    parts: [&'a [Token]; MAX_REMAINDER_PARTS],
    len: usize,
}

impl<'a> RawRemainder<'a> {
    fn empty() -> Self {
        Self {
            parts: [&[]; MAX_REMAINDER_PARTS],
            len: 0,
        }
    }

    fn prepend(mut self, tokens: &'a [Token]) -> Result<Self, String> {
        if tokens.is_empty() {
            return Ok(self);
        }
        if self.len == MAX_REMAINDER_PARTS {
            return Err(format!(
                "npm workspace extglob remainder exceeds the {MAX_REMAINDER_PARTS}-part limit"
            ));
        }
        self.parts.copy_within(0..self.len, 1);
        self.parts[0] = tokens;
        self.len += 1;
        Ok(self)
    }
}

/// Lower a parsed sequence into npm minimatch's placement-sensitive form.
/// Negative lookaheads receive owned copies of the exact suffix chain, which
/// mirrors minimatch's `fillNegs` pass and avoids reusing root-only `*` state.
#[allow(clippy::too_many_arguments)]
fn lower_sequence(
    sequence: &Sequence,
    is_start: bool,
    is_end: bool,
    component_root: bool,
    outer_remainder: RawRemainder<'_>,
    node_count: &mut usize,
) -> Result<Sequence, String> {
    let mut lowered = Vec::with_capacity(sequence.tokens.len());
    let mut may_still_start = is_start;
    for (index, token) in sequence.tokens.iter().enumerate() {
        let lowered_token = match token {
            Token::Literal(value) => Token::Literal(*value),
            Token::LiteralText(value) => Token::LiteralText(value.clone()),
            Token::AnyChar => Token::AnyChar,
            Token::Star { sole_in_part, .. } => Token::Star {
                sole_in_part: *sole_in_part,
                allow_empty: !(is_start && is_end && *sole_in_part),
            },
            Token::Class(class) => Token::Class(class.clone()),
            Token::Extglob {
                kind,
                alternatives,
                negative_non_empty_wildcard,
                copied_into_negative_suffix,
                original,
                ..
            } => {
                let extglob_start = may_still_start;
                let extglob_end = is_end && index + 1 == sequence.tokens.len();
                if *kind != ExtglobKind::Negated && extglob_start && extglob_end {
                    let has_non_empty = alternatives
                        .iter()
                        .any(|alternative| !alternative.tokens.is_empty());
                    if !has_non_empty {
                        if component_root && sequence.tokens.len() == 1 {
                            lowered.push(Token::LiteralText(original.clone()));
                            may_still_start = false;
                            continue;
                        }
                        if *kind == ExtglobKind::ExactlyOne {
                            // Once nested in another regexp, minimatch returns
                            // the raw `@()` source. Its parentheses are regexp
                            // syntax, so the accepted text is just `@`.
                            lowered.push(Token::LiteralText("@".to_owned()));
                            may_still_start = false;
                            continue;
                        }
                        let follows_only_negatives = index > 0
                            && sequence.tokens[..index].iter().all(|token| {
                                matches!(
                                    token,
                                    Token::Extglob {
                                        kind: ExtglobKind::Negated,
                                        ..
                                    }
                                )
                            });
                        if follows_only_negatives {
                            // Raw `?()`, `+()`, and `*()` quantify the preceding
                            // negative regexp. On non-empty path components the
                            // language is the same as that negative alone.
                            may_still_start = false;
                            continue;
                        }
                        return Err(
                            "mixed or nested empty npm workspace extglobs are not safely supported"
                                .to_owned(),
                        );
                    }
                }

                let remainder = outer_remainder.prepend(&sequence.tokens[index + 1..])?;
                let mut lowered_alternatives = Vec::new();
                let effective_negative_wildcard =
                    *negative_non_empty_wildcard && !*copied_into_negative_suffix;
                if *kind == ExtglobKind::Negated {
                    if !effective_negative_wildcard {
                        for alternative in alternatives {
                            let lowered_nodes = count_token_nodes(&alternative.tokens)
                                + remainder
                                    .parts
                                    .iter()
                                    .take(remainder.len)
                                    .map(|part| count_token_nodes(part))
                                    .sum::<usize>();
                            add_compiled_nodes(node_count, lowered_nodes)?;
                            let combined_len = alternative.tokens.len()
                                + remainder
                                    .parts
                                    .iter()
                                    .take(remainder.len)
                                    .map(|part| part.len())
                                    .sum::<usize>();
                            let mut combined = Vec::with_capacity(combined_len);
                            combined.extend_from_slice(&alternative.tokens);
                            for part in remainder.parts.iter().take(remainder.len) {
                                append_copied_negative_suffix(&mut combined, part);
                            }
                            lowered_alternatives.push(lower_sequence(
                                &Sequence {
                                    tokens: combined,
                                    at_component_start: false,
                                },
                                extglob_start,
                                true,
                                false,
                                RawRemainder::empty(),
                                node_count,
                            )?);
                        }
                    }
                } else {
                    for alternative in alternatives {
                        if extglob_start && extglob_end && alternative.tokens.is_empty() {
                            continue;
                        }
                        lowered_alternatives.push(lower_sequence(
                            alternative,
                            extglob_start,
                            extglob_end,
                            false,
                            remainder,
                            node_count,
                        )?);
                    }
                }
                Token::Extglob {
                    kind: *kind,
                    alternatives: lowered_alternatives,
                    at_component_start: extglob_start,
                    negative_non_empty_wildcard: effective_negative_wildcard,
                    copied_into_negative_suffix: *copied_into_negative_suffix,
                    original: original.clone(),
                }
            }
        };
        may_still_start &= matches!(
            &lowered_token,
            Token::Extglob {
                kind: ExtglobKind::Negated,
                ..
            }
        );
        lowered.push(lowered_token);
    }
    Ok(Sequence {
        tokens: lowered,
        at_component_start: is_start,
    })
}

fn append_copied_negative_suffix(output: &mut Vec<Token>, suffix: &[Token]) {
    for token in suffix {
        let mut copied = token.clone();
        copied.mark_copied_negative_suffix();
        output.push(copied);
    }
}

fn count_token_nodes(tokens: &[Token]) -> usize {
    tokens
        .iter()
        .map(|token| match token {
            Token::Extglob { alternatives, .. } => {
                1 + alternatives
                    .iter()
                    .map(|alternative| count_token_nodes(&alternative.tokens))
                    .sum::<usize>()
            }
            Token::Literal(_)
            | Token::LiteralText(_)
            | Token::AnyChar
            | Token::Star { .. }
            | Token::Class(_) => 1,
        })
        .sum()
}

fn add_compiled_nodes(node_count: &mut usize, amount: usize) -> Result<(), String> {
    *node_count = node_count.saturating_add(amount);
    if *node_count > MAX_AST_NODES {
        return Err(format!(
            "npm workspace pattern exceeds the {MAX_AST_NODES}-node syntax limit after extglob lowering"
        ));
    }
    Ok(())
}

impl PathPattern {
    fn is_match(&self, candidate: &[&str], context: &mut MatchContext) -> Result<bool, String> {
        let mut states = vec![false; candidate.len() + 1];
        states[0] = true;

        for (component_index, component) in self.components.iter().enumerate() {
            let mut next = vec![false; candidate.len() + 1];
            match component {
                PathComponent::GlobStar => {
                    for (start, active) in states.iter().copied().enumerate() {
                        if !active {
                            continue;
                        }
                        context.bump(1)?;
                        let trailing_after_prefix =
                            component_index > 0 && component_index + 1 == self.components.len();
                        if !trailing_after_prefix {
                            next[start] = true;
                        }
                        let mut end = start;
                        while end < candidate.len() && !candidate[end].starts_with('.') {
                            context.bump(1)?;
                            end += 1;
                            next[end] = true;
                        }
                    }
                }
                PathComponent::Pattern {
                    sequence: pattern,
                    unit_mode,
                } => {
                    for (start, active) in states.iter().copied().enumerate() {
                        if !active || start == candidate.len() {
                            continue;
                        }
                        context.bump(1)?;
                        if pattern.is_match(candidate[start], *unit_mode, context)? {
                            next[start + 1] = true;
                        }
                    }
                }
            }
            if !next.iter().any(|active| *active) {
                return Ok(false);
            }
            states = next;
        }

        Ok(states[candidate.len()])
    }
}

impl Sequence {
    fn is_match(
        &self,
        candidate: &str,
        unit_mode: UnitMode,
        context: &mut MatchContext,
    ) -> Result<bool, String> {
        let units = match unit_mode {
            UnitMode::Utf16 => candidate.encode_utf16().map(u32::from).collect::<Vec<_>>(),
            UnitMode::UnicodeScalar => candidate.chars().map(u32::from).collect::<Vec<_>>(),
        };
        let input = MatchInput {
            units: &units,
            ceiling: units.len(),
            unit_mode,
        };
        Ok(self
            .end_positions(input, vec![0], true, context)?
            .contains(&units.len()))
    }

    fn end_positions(
        &self,
        input: MatchInput<'_>,
        mut positions: Vec<usize>,
        honor_start_placement: bool,
        context: &mut MatchContext,
    ) -> Result<Vec<usize>, String> {
        if honor_start_placement
            && self.at_component_start
            && matches!(
                self.tokens.first(),
                Some(token) if !matches!(token, Token::Extglob { .. })
            )
            && !self.allows_leading_dot()
        {
            positions.retain(|position| input.units.get(*position) != Some(&u32::from('.')));
        }
        end_token_positions(
            &self.tokens,
            input,
            positions,
            honor_start_placement,
            context,
        )
    }

    fn allows_leading_dot(&self) -> bool {
        for token in &self.tokens {
            if token.explicitly_starts_with_dot() {
                return true;
            }
            if !token.can_defer_leading_dot() {
                return false;
            }
        }
        false
    }

    fn is_nullable(&self) -> bool {
        self.tokens.iter().all(Token::is_nullable)
    }

    fn requires_unicode_regexp(&self) -> bool {
        self.tokens.iter().any(Token::requires_unicode_regexp)
    }

    fn contains_invalid_unicode_identity_escape(&self) -> bool {
        self.tokens
            .iter()
            .any(Token::contains_invalid_unicode_identity_escape)
    }

    fn validate_empty_quantifiers(&self) -> Result<(), String> {
        for token in &self.tokens {
            if let Token::Extglob { alternatives, .. } = token {
                for alternative in alternatives {
                    alternative.validate_empty_quantifiers()?;
                }
            }
        }

        for adjacent in self.tokens.windows(2) {
            let broadening_negative = matches!(
                &adjacent[0],
                Token::Extglob {
                    kind: ExtglobKind::Negated,
                    negative_non_empty_wildcard: true,
                    ..
                }
            );
            let empty_quantifier = matches!(
                &adjacent[1],
                Token::Extglob {
                    kind: ExtglobKind::ZeroOrOne
                        | ExtglobKind::OneOrMore
                        | ExtglobKind::ZeroOrMore,
                    alternatives,
                    ..
                } if alternatives.iter().all(|alternative| alternative.tokens.is_empty())
            );
            if broadening_negative && empty_quantifier {
                return Err(
                    "npm workspace empty extglob would produce an invalid minimatch regular expression"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    fn validate_repeat_clone_sensitive_empty_exact(&self) -> Result<(), String> {
        for token in &self.tokens {
            let Token::Extglob {
                kind, alternatives, ..
            } = token
            else {
                continue;
            };
            for alternative in alternatives {
                alternative.validate_repeat_clone_sensitive_empty_exact()?;
            }
            if matches!(kind, ExtglobKind::OneOrMore | ExtglobKind::ZeroOrMore)
                && alternatives
                    .iter()
                    .any(Sequence::contains_empty_exact_extglob)
            {
                return Err(
                    "npm workspace repeated extglobs containing nested empty @() are not supported"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    fn contains_empty_exact_extglob(&self) -> bool {
        self.tokens.iter().any(|token| {
            let Token::Extglob {
                kind, alternatives, ..
            } = token
            else {
                return false;
            };
            (*kind == ExtglobKind::ExactlyOne
                && alternatives
                    .iter()
                    .all(|alternative| alternative.tokens.is_empty()))
                || alternatives
                    .iter()
                    .any(Sequence::contains_empty_exact_extglob)
        })
    }
}

fn end_token_positions(
    tokens: &[Token],
    input: MatchInput<'_>,
    mut positions: Vec<usize>,
    honor_start_placement: bool,
    context: &mut MatchContext,
) -> Result<Vec<usize>, String> {
    for token in tokens {
        let mut next = Vec::new();
        for position in positions {
            context.bump(1)?;
            token.end_positions(input, position, honor_start_placement, context, &mut next)?;
        }
        positions = deduplicate_positions(next, input.ceiling);
        if positions.is_empty() {
            break;
        }
    }
    Ok(positions)
}

impl Token {
    fn mark_copied_negative_suffix(&mut self) {
        if let Self::Extglob {
            alternatives,
            copied_into_negative_suffix,
            ..
        } = self
        {
            *copied_into_negative_suffix = true;
            for alternative in alternatives {
                for token in &mut alternative.tokens {
                    token.mark_copied_negative_suffix();
                }
            }
        }
    }

    fn requires_unicode_regexp(&self) -> bool {
        match self {
            Self::Class(class) => class.requires_unicode_regexp(),
            Self::Extglob { alternatives, .. } => {
                alternatives.iter().any(Sequence::requires_unicode_regexp)
            }
            Self::Literal(_) | Self::LiteralText(_) | Self::AnyChar | Self::Star { .. } => false,
        }
    }

    fn contains_invalid_unicode_identity_escape(&self) -> bool {
        match self {
            Self::Literal(value) => is_invalid_unicode_identity_escape(u32::from(*value)),
            Self::LiteralText(value) => value
                .chars()
                .map(u32::from)
                .any(is_invalid_unicode_identity_escape),
            Self::Class(class) => class.contains_invalid_unicode_identity_escape(),
            Self::Extglob { alternatives, .. } => alternatives
                .iter()
                .any(Sequence::contains_invalid_unicode_identity_escape),
            Self::AnyChar | Self::Star { .. } => false,
        }
    }

    fn end_positions(
        &self,
        input: MatchInput<'_>,
        position: usize,
        honor_start_placement: bool,
        context: &mut MatchContext,
        output: &mut Vec<usize>,
    ) -> Result<(), String> {
        match self {
            Self::Literal(expected) => {
                if let Some(end) = match_literal_character(*expected, input, position, context)? {
                    output.push(end);
                }
            }
            Self::LiteralText(expected) => {
                let mut end = position;
                for expected in expected.chars() {
                    let Some(next) = match_literal_character(expected, input, end, context)? else {
                        return Ok(());
                    };
                    end = next;
                }
                output.push(end);
            }
            Self::AnyChar => {
                if position < input.ceiling {
                    output.push(position + 1);
                }
            }
            Self::Star { allow_empty, .. } => {
                let first = position + usize::from(!allow_empty);
                for end in first..=input.ceiling {
                    context.bump(1)?;
                    output.push(end);
                }
            }
            Self::Class(class) => {
                if position < input.ceiling && class.matches(input.units[position], input.unit_mode)
                {
                    output.push(position + 1);
                }
            }
            Self::Extglob {
                kind,
                alternatives,
                at_component_start,
                negative_non_empty_wildcard,
                ..
            } => match kind {
                ExtglobKind::ExactlyOne => extend_alternative_positions(
                    alternatives,
                    input,
                    position,
                    honor_start_placement,
                    context,
                    output,
                )?,
                ExtglobKind::ZeroOrOne => {
                    output.push(position);
                    extend_alternative_positions(
                        alternatives,
                        input,
                        position,
                        honor_start_placement,
                        context,
                        output,
                    )?;
                }
                ExtglobKind::OneOrMore => extend_repeated_positions(
                    alternatives,
                    input,
                    position,
                    false,
                    honor_start_placement,
                    context,
                    output,
                )?,
                ExtglobKind::ZeroOrMore => extend_repeated_positions(
                    alternatives,
                    input,
                    position,
                    true,
                    honor_start_placement,
                    context,
                    output,
                )?,
                ExtglobKind::Negated => {
                    if honor_start_placement
                        && *at_component_start
                        && input.units.get(position) == Some(&u32::from('.'))
                    {
                        return Ok(());
                    }
                    if *negative_non_empty_wildcard
                        || !negative_lookahead_matches(
                            alternatives,
                            input,
                            position,
                            honor_start_placement,
                            context,
                        )?
                    {
                        let first = position + usize::from(*negative_non_empty_wildcard);
                        for end in first..=input.ceiling {
                            context.bump(1)?;
                            output.push(end);
                        }
                    }
                }
            },
        }
        Ok(())
    }

    fn explicitly_starts_with_dot(&self) -> bool {
        match self {
            Self::Literal(value) => *value == '.',
            Self::LiteralText(value) => value.starts_with('.'),
            Self::Class(class) => class.explicitly_includes('.'),
            Self::Extglob {
                kind:
                    ExtglobKind::ExactlyOne
                    | ExtglobKind::ZeroOrOne
                    | ExtglobKind::OneOrMore
                    | ExtglobKind::ZeroOrMore,
                alternatives,
                ..
            } => alternatives.iter().any(Sequence::allows_leading_dot),
            Self::AnyChar
            | Self::Star { .. }
            | Self::Extglob {
                kind: ExtglobKind::Negated,
                ..
            } => false,
        }
    }

    fn can_defer_leading_dot(&self) -> bool {
        match self {
            // A bare wildcard at the beginning still activates minimatch's
            // dot guard even when it can consume an empty string.
            Self::Star { .. } => false,
            Self::Extglob {
                kind: ExtglobKind::ZeroOrOne | ExtglobKind::ZeroOrMore,
                ..
            } => true,
            Self::Extglob {
                kind: ExtglobKind::ExactlyOne | ExtglobKind::OneOrMore,
                alternatives,
                ..
            } => alternatives.iter().any(Sequence::is_nullable),
            Self::Literal(_)
            | Self::LiteralText(_)
            | Self::AnyChar
            | Self::Class(_)
            | Self::Extglob {
                kind: ExtglobKind::Negated,
                ..
            } => false,
        }
    }

    fn is_nullable(&self) -> bool {
        match self {
            Self::Star { allow_empty, .. } => *allow_empty,
            Self::Extglob {
                kind: ExtglobKind::ZeroOrOne | ExtglobKind::ZeroOrMore,
                ..
            } => true,
            Self::Extglob {
                kind: ExtglobKind::ExactlyOne | ExtglobKind::OneOrMore,
                alternatives,
                ..
            } => alternatives.iter().any(Sequence::is_nullable),
            Self::Extglob {
                kind: ExtglobKind::Negated,
                negative_non_empty_wildcard,
                ..
            } => !negative_non_empty_wildcard,
            Self::Literal(_) | Self::LiteralText(_) | Self::AnyChar | Self::Class(_) => false,
        }
    }
}

fn match_literal_character(
    expected: char,
    input: MatchInput<'_>,
    position: usize,
    context: &mut MatchContext,
) -> Result<Option<usize>, String> {
    match input.unit_mode {
        UnitMode::UnicodeScalar => {
            context.bump(1)?;
            Ok(
                (position < input.ceiling && input.units[position] == u32::from(expected))
                    .then_some(position + 1),
            )
        }
        UnitMode::Utf16 => {
            let mut encoded = [0_u16; 2];
            let expected_units = expected.encode_utf16(&mut encoded);
            let mut end = position;
            for expected_unit in expected_units {
                context.bump(1)?;
                if end == input.ceiling || input.units[end] != u32::from(*expected_unit) {
                    return Ok(None);
                }
                end += 1;
            }
            Ok(Some(end))
        }
    }
}

fn extend_alternative_positions(
    alternatives: &[Sequence],
    input: MatchInput<'_>,
    position: usize,
    honor_start_placement: bool,
    context: &mut MatchContext,
    output: &mut Vec<usize>,
) -> Result<(), String> {
    for alternative in alternatives {
        context.bump(1)?;
        output.extend(alternative.end_positions(
            input,
            vec![position],
            honor_start_placement,
            context,
        )?);
    }
    Ok(())
}

fn negative_lookahead_matches(
    alternatives: &[Sequence],
    input: MatchInput<'_>,
    position: usize,
    honor_start_placement: bool,
    context: &mut MatchContext,
) -> Result<bool, String> {
    for alternative in alternatives {
        context.bump(1)?;
        if alternative
            .end_positions(input, vec![position], honor_start_placement, context)?
            .contains(&input.ceiling)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn extend_repeated_positions(
    alternatives: &[Sequence],
    input: MatchInput<'_>,
    position: usize,
    include_zero: bool,
    honor_start_placement: bool,
    context: &mut MatchContext,
    output: &mut Vec<usize>,
) -> Result<(), String> {
    let mut seen = vec![false; input.ceiling + 1];
    let mut frontier = vec![position];
    if include_zero {
        seen[position] = true;
        output.push(position);
    }

    let mut first_round = true;
    let mut scheduled_first_nullable = false;
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for start in frontier {
            let mut ends = Vec::new();
            extend_alternative_positions(
                alternatives,
                input,
                start,
                honor_start_placement && first_round,
                context,
                &mut ends,
            )?;
            for end in ends {
                context.bump(1)?;
                if !seen[end] {
                    seen[end] = true;
                    output.push(end);
                    next.push(end);
                    scheduled_first_nullable |= first_round && end == position;
                } else if first_round && end == position && !scheduled_first_nullable {
                    // One nullable alternative is still one occurrence. For
                    // zero-or-more, schedule that transition once so the
                    // continuation round can use its non-start dot behavior.
                    if !include_zero {
                        output.push(end);
                    }
                    next.push(end);
                    scheduled_first_nullable = true;
                }
            }
        }
        first_round = false;
        frontier = next;
    }
    Ok(())
}

impl CharacterClass {
    fn matches(&self, candidate: u32, unit_mode: UnitMode) -> bool {
        let items = match unit_mode {
            UnitMode::Utf16 => &self.utf16_items,
            UnitMode::UnicodeScalar => &self.unicode_items,
        };
        if items.is_empty() {
            return false;
        }
        let mut normal_present = false;
        let mut normal_match = false;
        let mut graph_present = false;
        let mut graph_match = false;
        for item in items {
            if matches!(item, ClassItem::Posix(PosixClass::Graph)) {
                graph_present = true;
                graph_match |= item.matches(candidate);
            } else {
                normal_present = true;
                normal_match |= item.matches(candidate);
            }
        }
        if self.negated {
            (normal_present && !normal_match) || (graph_present && !graph_match)
        } else {
            normal_match || graph_match
        }
    }

    fn explicitly_includes(&self, candidate: char) -> bool {
        let mixed_graph_source = self
            .unicode_items
            .iter()
            .any(|item| matches!(item, ClassItem::Posix(PosixClass::Graph)))
            && self
                .unicode_items
                .iter()
                .any(|item| !matches!(item, ClassItem::Posix(PosixClass::Graph)));
        mixed_graph_source
            || !self.negated
                && matches!(
                    self.unicode_items.as_slice(),
                    [ClassItem::Character(value)] if *value == u32::from(candidate)
                )
            || !self.negated
                && matches!(
                    self.unicode_items.as_slice(),
                    [ClassItem::Range(start, end)]
                        if *start == u32::from(candidate) && start == end
                )
    }

    fn requires_unicode_regexp(&self) -> bool {
        self.unicode_items
            .iter()
            .any(|item| matches!(item, ClassItem::Posix(class) if class.requires_unicode_regexp()))
    }

    fn contains_invalid_unicode_identity_escape(&self) -> bool {
        if self.negated {
            return false;
        }
        match self.utf16_items.as_slice() {
            [ClassItem::Character(value)] => {
                is_invalid_unicode_identity_escape(*value)
                    && !is_javascript_dot_line_terminator(*value)
            }
            [ClassItem::Range(start, end)] if start == end => {
                is_invalid_unicode_identity_escape(*start)
                    && !is_javascript_dot_line_terminator(*start)
            }
            _ => false,
        }
    }
}

fn is_javascript_dot_line_terminator(value: u32) -> bool {
    matches!(value, 0x000a | 0x000d | 0x2028 | 0x2029)
}

fn is_invalid_unicode_identity_escape(value: u32) -> bool {
    matches!(
        value,
        0x2d | 0x2c | 0x23
            | 0x0009..=0x000d
            | 0x0020
            | 0x00a0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
            | 0xfeff
    )
}

impl ClassItem {
    fn matches(&self, candidate: u32) -> bool {
        match self {
            Self::Character(value) => candidate == *value,
            Self::Range(start, end) => (*start..=*end).contains(&candidate),
            Self::Posix(class) => {
                char::from_u32(candidate).is_some_and(|candidate| class.matches(candidate))
            }
        }
    }
}

impl PosixClass {
    fn parse(name: &str) -> Result<Self, String> {
        match name {
            "alnum" => Ok(Self::Alnum),
            "alpha" => Ok(Self::Alpha),
            "ascii" => Ok(Self::Ascii),
            "blank" => Ok(Self::Blank),
            "cntrl" => Ok(Self::Cntrl),
            "digit" => Ok(Self::Digit),
            "graph" => Ok(Self::Graph),
            "lower" => Ok(Self::Lower),
            "print" => Ok(Self::Print),
            "punct" => Ok(Self::Punct),
            "space" => Ok(Self::Space),
            "upper" => Ok(Self::Upper),
            "word" => Ok(Self::Word),
            "xdigit" => Ok(Self::Xdigit),
            _ => Err(format!("unsupported POSIX character class {name:?}")),
        }
    }

    fn matches(self, candidate: char) -> bool {
        let category = get_general_category(candidate);
        match self {
            Self::Alnum => {
                is_unicode_letter(category)
                    || matches!(
                        category,
                        GeneralCategory::LetterNumber | GeneralCategory::DecimalNumber
                    )
            }
            Self::Alpha => is_unicode_letter(category) || category == GeneralCategory::LetterNumber,
            Self::Ascii => candidate.is_ascii(),
            Self::Blank => category == GeneralCategory::SpaceSeparator || candidate == '\t',
            Self::Cntrl => category == GeneralCategory::Control,
            Self::Digit => category == GeneralCategory::DecimalNumber,
            Self::Graph => !is_unicode_separator(category) && !is_unicode_other(category),
            Self::Lower => category == GeneralCategory::LowercaseLetter,
            // This intentionally mirrors minimatch 9's `[:print:]` mapping to
            // Unicode General_Category=C, even though the POSIX class name is
            // surprising. Workspace identity proof must follow npm exactly.
            Self::Print => is_unicode_other(category),
            Self::Punct => is_unicode_punctuation(category),
            Self::Space => {
                is_unicode_separator(category)
                    || matches!(candidate, '\t' | '\r' | '\n' | '\u{000b}' | '\u{000c}')
            }
            Self::Upper => category == GeneralCategory::UppercaseLetter,
            Self::Word => {
                is_unicode_letter(category)
                    || matches!(
                        category,
                        GeneralCategory::LetterNumber
                            | GeneralCategory::DecimalNumber
                            | GeneralCategory::ConnectorPunctuation
                    )
            }
            Self::Xdigit => candidate.is_ascii_hexdigit(),
        }
    }

    fn requires_unicode_regexp(self) -> bool {
        !matches!(self, Self::Ascii | Self::Xdigit)
    }
}

fn is_unicode_letter(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::LowercaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::UppercaseLetter
    )
}

fn is_unicode_separator(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
    )
}

fn is_unicode_other(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::PrivateUse
            | GeneralCategory::Surrogate
            | GeneralCategory::Unassigned
    )
}

fn is_unicode_punctuation(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::ClosePunctuation
            | GeneralCategory::ConnectorPunctuation
            | GeneralCategory::DashPunctuation
            | GeneralCategory::FinalPunctuation
            | GeneralCategory::InitialPunctuation
            | GeneralCategory::OpenPunctuation
            | GeneralCategory::OtherPunctuation
    )
}

struct ComponentParser<'a> {
    chars: Vec<char>,
    position: usize,
    nesting: usize,
    node_count: &'a mut usize,
}

impl<'a> ComponentParser<'a> {
    fn new(component: &str, node_count: &'a mut usize) -> Self {
        Self {
            chars: component.chars().collect(),
            position: 0,
            nesting: 0,
            node_count,
        }
    }

    fn parse_top_level(&mut self) -> Result<Sequence, String> {
        let sequence = self.parse_sequence(false)?;
        if self.position != self.chars.len() {
            return Err("npm workspace pattern contains an unexpected delimiter".to_owned());
        }
        Ok(sequence)
    }

    fn parse_sequence(&mut self, inside_extglob: bool) -> Result<Sequence, String> {
        let mut tokens = Vec::new();
        while let Some(current) = self.chars.get(self.position).copied() {
            if inside_extglob && matches!(current, '|' | ')') {
                break;
            }
            let next = self.chars.get(self.position + 1).copied();
            if matches!(current, '@' | '?' | '+' | '*' | '!') && next == Some('(') {
                if self.extglob_is_closed(self.position) {
                    tokens.push(self.parse_extglob(current)?);
                    continue;
                }
                return Err("unmatched npm workspace extglob openers are not supported".to_owned());
            }
            let token = match current {
                '*' => {
                    self.position += 1;
                    Token::Star {
                        sole_in_part: false,
                        allow_empty: true,
                    }
                }
                '?' => {
                    self.position += 1;
                    Token::AnyChar
                }
                '[' if self.class_is_closed(self.position) => self.parse_class()?,
                '[' => {
                    self.position += 1;
                    Token::Literal('[')
                }
                literal => {
                    self.position += 1;
                    Token::Literal(literal)
                }
            };
            self.add_node()?;
            tokens.push(token);
        }
        mark_plain_star_parts(&mut tokens);
        Ok(Sequence {
            tokens,
            at_component_start: false,
        })
    }

    fn extglob_is_closed(&self, start: usize) -> bool {
        let mut depth = 1usize;
        let mut in_class = false;
        let mut cursor = start + 2;
        while cursor < self.chars.len() {
            match self.chars[cursor] {
                '[' => in_class = true,
                ']' => in_class = false,
                '@' | '?' | '+' | '*' | '!'
                    if !in_class && self.chars.get(cursor + 1) == Some(&'(') =>
                {
                    depth += 1;
                    cursor += 1;
                }
                ')' if !in_class => {
                    depth -= 1;
                    if depth == 0 {
                        return true;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        false
    }

    fn class_is_closed(&self, start: usize) -> bool {
        let mut cursor = start + 1;
        if matches!(self.chars.get(cursor), Some('!') | Some('^')) {
            cursor += 1;
        }
        if self.chars.get(cursor) == Some(&']') {
            cursor += 1;
        }
        while cursor < self.chars.len() {
            if self.chars[cursor] == ']' {
                return true;
            }
            if self.chars[cursor] == '[' && self.chars.get(cursor + 1) == Some(&':') {
                cursor += 2;
                while cursor + 1 < self.chars.len()
                    && !(self.chars[cursor] == ':' && self.chars[cursor + 1] == ']')
                {
                    cursor += 1;
                }
                if cursor + 1 >= self.chars.len() {
                    return false;
                }
                cursor += 2;
            } else {
                cursor += 1;
            }
        }
        false
    }

    fn parse_extglob(&mut self, operator: char) -> Result<Token, String> {
        let start = self.position;
        self.nesting += 1;
        if self.nesting > MAX_NESTING {
            return Err(format!(
                "npm workspace extglob exceeds the {MAX_NESTING}-level nesting limit"
            ));
        }
        self.position += 2;
        let mut alternatives = Vec::new();
        loop {
            alternatives.push(self.parse_sequence(true)?);
            match self.chars.get(self.position).copied() {
                Some('|') => self.position += 1,
                Some(')') => {
                    self.position += 1;
                    break;
                }
                None => {
                    return Err("npm workspace extglob has an unclosed parenthesis".to_owned());
                }
                Some(_) => unreachable!("extglob sequence stops only at a delimiter"),
            }
            if alternatives.len() >= MAX_BRACE_EXPANSIONS {
                return Err(format!(
                    "npm workspace extglob exceeds the {MAX_BRACE_EXPANSIONS}-alternative limit"
                ));
            }
        }
        self.nesting -= 1;
        self.add_node()?;
        let kind = match operator {
            '@' => ExtglobKind::ExactlyOne,
            '?' => ExtglobKind::ZeroOrOne,
            '+' => ExtglobKind::OneOrMore,
            '*' => ExtglobKind::ZeroOrMore,
            '!' => ExtglobKind::Negated,
            _ => unreachable!("caller recognizes extglob operators"),
        };
        let negative_non_empty_wildcard = kind == ExtglobKind::Negated
            && alternatives.last().is_some_and(|alternative| {
                alternative.tokens.is_empty()
                    || matches!(alternative.tokens.last(), Some(Token::Extglob { .. }))
            });
        let original = self.chars[start..self.position].iter().collect();
        Ok(Token::Extglob {
            kind,
            alternatives,
            at_component_start: false,
            negative_non_empty_wildcard,
            copied_into_negative_suffix: false,
            original,
        })
    }

    fn parse_class(&mut self) -> Result<Token, String> {
        self.position += 1;
        let mut negated = false;
        if matches!(self.chars.get(self.position), Some('!') | Some('^')) {
            negated = true;
            self.position += 1;
        }

        let mut pieces = Vec::new();
        if self.chars.get(self.position) == Some(&']') {
            pieces.push(ClassPiece::Character(']'));
            self.position += 1;
        }
        let mut closed = false;
        while let Some(current) = self.chars.get(self.position).copied() {
            if current == ']' {
                self.position += 1;
                closed = true;
                break;
            }
            if current == '[' && self.chars.get(self.position + 1) == Some(&':') {
                let name_start = self.position + 2;
                let mut cursor = name_start;
                while cursor + 1 < self.chars.len()
                    && !(self.chars[cursor] == ':' && self.chars[cursor + 1] == ']')
                {
                    cursor += 1;
                }
                if cursor + 1 >= self.chars.len() {
                    return Err("npm workspace POSIX class is not closed".to_owned());
                }
                let name = self.chars[name_start..cursor].iter().collect::<String>();
                pieces.push(ClassPiece::Posix(PosixClass::parse(&name)?));
                self.position = cursor + 2;
            } else {
                pieces.push(ClassPiece::Character(current));
                self.position += 1;
            }
        }
        if !closed {
            return Err("npm workspace character class is not closed".to_owned());
        }
        if pieces.is_empty() {
            return Err("npm workspace character class must not be empty".to_owned());
        }
        if pieces
            .iter()
            .any(|piece| matches!(piece, ClassPiece::Character(value) if value.len_utf16() == 2))
            && pieces
                .iter()
                .any(|piece| matches!(piece, ClassPiece::Character('-')))
        {
            return Err(
                "npm workspace character classes combining non-BMP characters with hyphens are not supported"
                    .to_owned(),
            );
        }

        let (utf16_items, unicode_items) = compile_character_class_items(&pieces);
        self.add_node()?;
        Ok(Token::Class(CharacterClass {
            negated,
            unicode_items,
            utf16_items,
        }))
    }

    fn add_node(&mut self) -> Result<(), String> {
        *self.node_count += 1;
        if *self.node_count > MAX_AST_NODES {
            return Err(format!(
                "npm workspace pattern exceeds the {MAX_AST_NODES}-node syntax limit"
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
enum ClassPiece {
    Character(char),
    Posix(PosixClass),
}

#[derive(Debug, Clone, Copy)]
enum Utf16ClassPiece {
    Unit(u16),
    Posix(PosixClass),
}

fn compile_character_class_items(pieces: &[ClassPiece]) -> (Vec<ClassItem>, Vec<ClassItem>) {
    let mut utf16_pieces = Vec::new();
    for piece in pieces {
        match piece {
            ClassPiece::Character(value) => {
                let mut encoded = [0_u16; 2];
                utf16_pieces.extend(
                    value
                        .encode_utf16(&mut encoded)
                        .iter()
                        .copied()
                        .map(Utf16ClassPiece::Unit),
                );
            }
            ClassPiece::Posix(class) => utf16_pieces.push(Utf16ClassPiece::Posix(*class)),
        }
    }

    let mut utf16_items = Vec::new();
    let mut range_start = None;
    let mut index = 0usize;
    while index < utf16_pieces.len() {
        match (range_start.take(), utf16_pieces[index]) {
            (Some(start), Utf16ClassPiece::Unit(end)) => {
                if end > start {
                    utf16_items.push(ClassItem::Range(u32::from(start), u32::from(end)));
                } else if end == start {
                    utf16_items.push(ClassItem::Character(u32::from(end)));
                }
                index += 1;
            }
            // minimatch poisons a class when a POSIX fragment terminates a
            // pending range, returning a never-match expression with no `/u`.
            (Some(_), Utf16ClassPiece::Posix(_)) => return (Vec::new(), Vec::new()),
            (None, Utf16ClassPiece::Posix(class)) => {
                utf16_items.push(ClassItem::Posix(class));
                index += 1;
            }
            (None, Utf16ClassPiece::Unit(value)) => {
                let next_is_hyphen = matches!(
                    utf16_pieces.get(index + 1),
                    Some(Utf16ClassPiece::Unit(unit)) if *unit == u16::from(b'-')
                );
                if next_is_hyphen && index + 2 == utf16_pieces.len() {
                    utf16_items.push(ClassItem::Character(u32::from(value)));
                    utf16_items.push(ClassItem::Character(u32::from(b'-')));
                    index += 2;
                } else if next_is_hyphen {
                    range_start = Some(value);
                    index += 2;
                } else {
                    utf16_items.push(ClassItem::Character(u32::from(value)));
                    index += 1;
                }
            }
        }
    }

    let unicode_items = decode_unicode_class_items(&utf16_items);
    (utf16_items, unicode_items)
}

fn decode_unicode_class_items(utf16_items: &[ClassItem]) -> Vec<ClassItem> {
    let mut unicode_items = Vec::with_capacity(utf16_items.len());
    let mut index = 0usize;
    while index < utf16_items.len() {
        if let (Some(ClassItem::Character(high)), Some(ClassItem::Character(low))) =
            (utf16_items.get(index), utf16_items.get(index + 1))
            && (0xd800..=0xdbff).contains(high)
            && (0xdc00..=0xdfff).contains(low)
        {
            let scalar = 0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00);
            unicode_items.push(ClassItem::Character(scalar));
            index += 2;
            continue;
        }
        unicode_items.push(utf16_items[index].clone());
        index += 1;
    }
    unicode_items
}

fn expand_braces(pattern: &str) -> Result<Vec<String>, String> {
    let mut pending = vec![pattern.to_owned()];
    let mut complete = Vec::new();
    let mut seen = HashSet::new();

    while let Some(candidate) = pending.pop() {
        if !seen.insert(candidate.clone()) {
            continue;
        }
        let chars = candidate.chars().collect::<Vec<_>>();
        if let Some((open, close, replacements)) = find_expandable_brace(&chars)? {
            if pending.len() + complete.len() + replacements.len() > MAX_BRACE_EXPANSIONS {
                return Err(format!(
                    "npm workspace brace expansion exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
                ));
            }
            let prefix = chars[..open].iter().collect::<String>();
            let suffix = chars[close + 1..].iter().collect::<String>();
            for replacement in replacements.into_iter().rev() {
                pending.push(format!("{prefix}{replacement}{suffix}"));
            }
        } else {
            complete.push(candidate);
        }
    }

    complete.sort();
    if complete.len() > MAX_BRACE_EXPANSIONS {
        return Err(format!(
            "npm workspace brace expansion exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
        ));
    }
    Ok(complete)
}

fn find_expandable_brace(chars: &[char]) -> Result<Option<(usize, usize, Vec<String>)>, String> {
    let mut stack = Vec::new();
    let mut protected_depth = 0usize;
    for (index, current) in chars.iter().copied().enumerate() {
        if protected_depth > 0 {
            match current {
                '{' => protected_depth += 1,
                '}' => protected_depth -= 1,
                _ => {}
            }
            continue;
        }
        match current {
            '{' if index > 0 && chars[index - 1] == '$' => protected_depth = 1,
            '{' => {
                if stack.len() >= MAX_NESTING {
                    return Err(format!(
                        "npm workspace brace expression exceeds the {MAX_NESTING}-level nesting limit"
                    ));
                }
                stack.push(index);
            }
            '}' => {
                let Some(open) = stack.pop() else {
                    continue;
                };
                let inner = &chars[open + 1..index];
                if let Some(replacements) = brace_replacements(inner)? {
                    return Ok(Some((open, index, replacements)));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

fn brace_replacements(inner: &[char]) -> Result<Option<Vec<String>>, String> {
    let comma_parts = split_top_level(inner, ',');
    if comma_parts.len() > 1 {
        return Ok(Some(
            comma_parts
                .into_iter()
                .map(|part| part.iter().collect::<String>())
                .collect(),
        ));
    }

    let range_parts = split_range_parts(inner);
    if range_parts.len() != 2 && range_parts.len() != 3 {
        return Ok(None);
    }
    if range_parts.iter().any(|part| part.starts_with('+')) {
        return Ok(None);
    }
    if let Some((start, end)) = parse_integer(&range_parts[0]).zip(parse_integer(&range_parts[1])) {
        return expand_numeric_range(&range_parts, start, end).map(Some);
    }
    if let Some((start, end)) =
        parse_alpha_endpoint(&range_parts[0]).zip(parse_alpha_endpoint(&range_parts[1]))
    {
        return expand_alpha_range(&range_parts, start, end).map(Some);
    }
    Ok(None)
}

fn range_step(parts: &[String], kind: &str) -> Result<u64, String> {
    if parts.len() != 3 {
        return Ok(1);
    }
    let Some(step) = parse_integer(&parts[2]) else {
        return Err(format!(
            "npm workspace {kind} brace range has a non-numeric step"
        ));
    };
    if step == 0 {
        return Err(format!("npm workspace {kind} brace range has a zero step"));
    }
    Ok(step.unsigned_abs())
}

fn expand_numeric_range(parts: &[String], start: i64, end: i64) -> Result<Vec<String>, String> {
    let step = range_step(parts, "numeric")?;

    let distance = start.abs_diff(end);
    let result_count = distance / step + 1;
    if result_count > MAX_BRACE_EXPANSIONS as u64 {
        return Err(format!(
            "npm workspace numeric brace range exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
        ));
    }

    let width = numeric_padding_width(&parts[0]).max(numeric_padding_width(&parts[1]));
    let direction = if start <= end { 1_i128 } else { -1_i128 };
    let signed_step = direction * i128::from(step);
    let mut value = i128::from(start);
    let end = i128::from(end);
    let mut replacements = Vec::with_capacity(result_count as usize);
    loop {
        replacements.push(format_range_value(value, width));
        if value == end {
            break;
        }
        let next = value + signed_step;
        if (direction > 0 && next > end) || (direction < 0 && next < end) {
            break;
        }
        value = next;
    }
    Ok(replacements)
}

fn parse_alpha_endpoint(value: &str) -> Option<char> {
    let mut chars = value.chars();
    let endpoint = chars.next()?;
    if chars.next().is_none() && endpoint.is_ascii_alphabetic() {
        Some(endpoint)
    } else {
        None
    }
}

fn expand_alpha_range(parts: &[String], start: char, end: char) -> Result<Vec<String>, String> {
    let step = range_step(parts, "alphabetic")?;
    let start = u32::from(start);
    let end = u32::from(end);
    let distance = start.abs_diff(end);
    let result_count = u64::from(distance) / step + 1;
    if result_count > MAX_BRACE_EXPANSIONS as u64 {
        return Err(format!(
            "npm workspace alphabetic brace range exceeds the {MAX_BRACE_EXPANSIONS}-result limit"
        ));
    }

    let direction = if start <= end { 1_i64 } else { -1_i64 };
    let signed_step = direction
        * i64::try_from(step)
            .map_err(|_| "npm workspace alphabetic brace range step is too large".to_owned())?;
    let mut value = i64::from(start);
    let end = i64::from(end);
    let mut replacements = Vec::with_capacity(result_count as usize);
    loop {
        let character = char::from_u32(u32::try_from(value).map_err(|_| {
            "npm workspace alphabetic brace range produced an invalid character".to_owned()
        })?)
        .ok_or_else(|| {
            "npm workspace alphabetic brace range produced an invalid character".to_owned()
        })?;
        replacements.push(character.to_string());
        if value == end {
            break;
        }
        let next = value + signed_step;
        if (direction > 0 && next > end) || (direction < 0 && next < end) {
            break;
        }
        value = next;
    }
    Ok(replacements)
}

fn split_top_level(chars: &[char], delimiter: char) -> Vec<&[char]> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut braces = 0usize;
    for (index, current) in chars.iter().copied().enumerate() {
        match current {
            '{' => braces += 1,
            '}' => braces = braces.saturating_sub(1),
            value if value == delimiter && braces == 0 => {
                parts.push(&chars[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&chars[start..]);
    parts
}

fn split_range_parts(chars: &[char]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index + 1 < chars.len() {
        if chars[index] == '.' && chars[index + 1] == '.' {
            parts.push(chars[start..index].iter().collect());
            index += 2;
            start = index;
        } else {
            index += 1;
        }
    }
    parts.push(chars[start..].iter().collect());
    parts
}

fn parse_integer(value: &str) -> Option<i64> {
    if value.is_empty() || value.starts_with('+') || value == "-" {
        return None;
    }
    value.parse().ok()
}

fn numeric_padding_width(value: &str) -> usize {
    let digits = value.trim_start_matches(['+', '-']);
    if digits.len() > 1 && digits.starts_with('0') {
        value.len()
    } else {
        0
    }
}

fn format_range_value(value: i128, width: usize) -> String {
    if width == 0 {
        return value.to_string();
    }
    if value < 0 {
        let digit_width = width.saturating_sub(1);
        format!("-{:0digit_width$}", value.unsigned_abs())
    } else {
        format!("{value:0width$}")
    }
}

fn deduplicate_positions(positions: Vec<usize>, ceiling: usize) -> Vec<usize> {
    let mut seen = vec![false; ceiling + 1];
    let mut deduplicated = Vec::new();
    for position in positions {
        if !seen[position] {
            seen[position] = true;
            deduplicated.push(position);
        }
    }
    deduplicated
}

#[derive(Debug, Default)]
struct MatchContext {
    work: usize,
}

impl MatchContext {
    fn bump(&mut self, amount: usize) -> Result<(), String> {
        self.work = self.work.saturating_add(amount);
        if self.work > MAX_MATCH_WORK {
            return Err(format!(
                "npm workspace match exceeds the {MAX_MATCH_WORK}-operation limit"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_BRACE_EXPANSIONS, MAX_WORKSPACE_PATTERNS, NpmMinimatch};
    use std::collections::BTreeSet;

    fn matches(pattern: &str, candidate: &str) -> bool {
        NpmMinimatch::compile(pattern)
            .unwrap()
            .is_match(candidate)
            .unwrap()
    }

    #[test]
    fn matches_wildcards_without_crossing_slashes() {
        assert!(matches("packages/*", "packages/api"));
        assert!(!matches("packages/*", "packages/api/client"));
        assert!(matches("packages/app?", "packages/apps"));
        assert!(!matches("packages/app?", "packages/app"));
        assert!(matches("packages/**/client", "packages/client"));
        assert!(matches(
            "packages/**/client",
            "packages/api/generated/client"
        ));
        assert!(!matches("packages/**/client", "other/client"));
        assert!(!matches("packages/**", "packages"));
        assert!(matches("packages/**", "packages/api"));
        assert!(matches("**/packages", "packages"));
    }

    #[test]
    fn applies_dot_false_to_every_component() {
        assert!(!matches("*", ".root"));
        assert!(!matches("packages/*", "packages/.hidden"));
        assert!(!matches("**/client", ".cache/client"));
        assert!(matches("packages/.*", "packages/.hidden"));
        assert!(matches("packages/[.]hidden", "packages/.hidden"));
        assert!(!matches("packages/[.a]hidden", "packages/.hidden"));
        assert!(!matches("packages/[.-0]hidden", "packages/.hidden"));
        assert!(!matches("packages/[[:punct:]]hidden", "packages/.hidden"));
        assert!(!matches("packages/[^a]*", "packages/.hidden"));
    }

    #[test]
    fn matches_character_classes_and_posix_classes() {
        assert!(matches("packages/[ab]", "packages/a"));
        assert!(matches("packages/[a-c]", "packages/b"));
        assert!(!matches("packages/[!a-c]", "packages/b"));
        assert!(matches("packages/[^a-c]", "packages/z"));
        assert!(matches("packages/[[:alpha:]]", "packages/q"));
        assert!(matches("packages/[[:alpha:]]", "packages/λ"));
        assert!(!matches("packages/[[:alpha:]]", "packages/7"));
        assert!(matches("packages/[[:punct:]]", "packages/!"));
        assert!(!matches("packages/[[:punct:]]", "packages/$"));
        assert!(matches("packages/[[:digit:]]", "packages/\u{0661}"));
        assert!(matches("packages/[[:word:]]", "packages/\u{2163}"));
        assert!(!matches("packages/[[:alnum:]]", "packages/\u{00bd}"));
        assert!(!matches("packages/[[:upper:]]", "packages/\u{2163}"));
        assert!(!matches("packages/[[:graph:]]", "packages/\u{200c}"));
        assert!(!matches("packages/[[:print:]]", "packages/a"));
        assert!(matches("packages/[[:print:]]", "packages/\u{200c}"));
        assert!(NpmMinimatch::compile("packages/[[:unknown:]]").is_err());
    }

    #[test]
    fn expands_comma_nested_and_ranged_braces_with_bounds() {
        assert!(matches("packages/{api,web}", "packages/api"));
        assert!(matches("packages/{,a}", "packages/a"));
        assert!(!matches("packages/{,a}", "packages"));
        assert!(matches("packages/{api,{web,worker}}", "packages/worker"));
        assert!(matches("{packages/api,apps/web}", "packages/api"));
        assert!(matches("{packages/api,apps/web}", "apps/web"));
        assert!(matches("packages/v{1..3}", "packages/v2"));
        assert!(matches("packages/v{03..01}", "packages/v02"));
        assert!(matches("packages/{-01..01}", "packages/000"));
        assert!(matches("packages/{-01..01}", "packages/001"));
        assert!(!matches("packages/{-01..01}", "packages/00"));
        assert!(matches("packages/v{1..5..2}", "packages/v3"));
        assert!(!matches("packages/v{1..5..2}", "packages/v4"));
        assert!(matches("packages/{a..c}", "packages/b"));
        assert!(matches("packages/{A..C}", "packages/B"));
        assert!(matches("packages/{a..e..2}", "packages/c"));
        assert!(!matches("packages/{a..e..2}", "packages/b"));
        assert!(matches("packages/{e..a..2}", "packages/c"));
        assert!(matches("packages/{literal}", "packages/{literal}"));
        assert!(!matches("packages/{literal}", "packages/literal"));
        // npm brace expansion runs before class and extglob parsing. Braces
        // inside a would-be class expand, and commas inside brackets remain
        // brace delimiters rather than class contents.
        assert!(matches("packages/[{a,b}]", "packages/a"));
        assert!(matches("packages/[{a,b}]", "packages/b"));
        assert!(!matches("packages/[{a,b}]", "packages/{"));
        assert!(!matches("packages/[{a,b}]", "packages/,"));
        assert!(matches("packages/[{1..3}]", "packages/2"));
        assert!(!matches("packages/[{1..3}]", "packages/{"));
        assert!(matches("packages/{[,],x}", "packages/["));
        assert!(matches("packages/{[,],x}", "packages/]"));
        assert!(matches("packages/{[,],x}", "packages/x"));
        assert!(!matches("packages/{[,],x}", "packages/,"));
        assert!(matches("packages/${a,b}", "packages/${a,b}"));
        assert!(!matches("packages/${a,b}", "packages/$a"));
        assert!(!matches("packages/${a,b}", "packages/$b"));
        assert!(matches("packages/x${a,b}y", "packages/x${a,b}y"));
        assert!(matches("packages/${{a,b},c}", "packages/${{a,b},c}"));
        assert!(matches("packages/$x{a,b}", "packages/$xa"));
        assert!(matches("packages/$x{a,b}", "packages/$xb"));
        for pattern in [
            "packages/@(!(a)",
            "packages/a@(!(b)",
            "packages/@(?(a)",
            "packages/@({a,!(x,y)}|z)",
            "packages/**(b",
            "packages/**({b,#}",
        ] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("unmatched npm workspace extglob openers"));
        }
        assert!(matches("packages/{+1..+3}", "packages/{+1..+3}"));
        assert!(!matches("packages/{+1..+3}", "packages/1"));
        assert!(matches("packages/{1..3..+1}", "packages/{1..3..+1}"));
        assert!(!matches("packages/{1..3..+1}", "packages/2"));

        let over_limit = format!("packages/{{1..{}}}", MAX_BRACE_EXPANSIONS + 1);
        assert!(NpmMinimatch::compile(&over_limit).is_err());
        assert!(NpmMinimatch::compile("packages/{1..3..0}").is_err());
    }

    #[test]
    fn matches_all_extglob_operators() {
        assert!(matches("packages/@(api|web)", "packages/api"));
        assert!(!matches("packages/@(api|web)", "packages/worker"));

        assert!(matches("packages/item?(s|z)", "packages/item"));
        assert!(matches("packages/item?(s|z)", "packages/items"));
        assert!(!matches("packages/item?(s|z)", "packages/itemss"));

        assert!(matches("packages/+(ab|c)", "packages/abcab"));
        assert!(!matches("packages/+(ab|c)", "packages/x"));

        assert!(matches("packages/x*(ab|c)", "packages/x"));
        assert!(matches("packages/x*(ab|c)", "packages/xabc"));

        assert!(matches("packages/!(api|web)", "packages/worker"));
        assert!(!matches("packages/!(api|web)", "packages/api"));

        // Negative lookaheads include the complete component remainder.
        assert!(matches("packages/pre!(bad).js", "packages/pregood.js"));
        assert!(matches("packages/pre!(bad).js", "packages/pre.js"));
        assert!(!matches("packages/pre!(bad).js", "packages/prebad.js"));
        assert!(matches("packages/!(a)*", "packages/a"));
        assert!(!matches("packages/!(a)*", "packages/ac"));
        assert!(matches("packages/!(a)*", "packages/bc"));
        assert!(matches("packages/!(a)b", "packages/b"));
        assert!(!matches("packages/!(a)b", "packages/ab"));
        assert!(matches("packages/a!(b)c", "packages/ac"));
        assert!(!matches("packages/a!(b)c", "packages/abc"));
        assert!(matches("packages/a!(b)c", "packages/axc"));

        // npm minimatch treats a slash inside an extglob as a path-component
        // split that can never match the intended alternatives. Rejecting it
        // makes that unsupported construction visible to the caller.
        let cross_component = NpmMinimatch::compile("@(packages/a|packages/b)").unwrap_err();
        assert!(cross_component.contains("must not cross path separators"));

        // A plain part that is exactly `*` is non-empty next to an extglob;
        // repeated `**` remains two nullable stars.
        assert!(!matches("packages/*@(a|b)", "packages/a"));
        assert!(matches("packages/*@(a|b)", "packages/aa"));
        assert!(!matches("packages/@(a|b)*", "packages/a"));
        assert!(matches("packages/@(a|b)*", "packages/ab"));
        assert!(matches("packages/**@(a|b)", "packages/a"));
        assert!(matches("packages/@(a|b)**", "packages/a"));
        assert!(matches("packages/@(a*|b)", "packages/a"));

        // These are non-intuitive but observable npm 11/minimatch 9 rules.
        // A negative whose final alternative ends in an extglob becomes a
        // non-empty wildcard, while a nested negative in a positive extglob
        // keeps the copied suffix lookahead.
        assert!(matches("packages/!(@(foo|bar)).js", "packages/foo.js"));
        assert!(!matches("packages/!(@(foo|bar)).js", "packages/.js"));
        assert!(!matches("packages/@(!(foo)|bar).js", "packages/foo.js"));
        assert!(matches("packages/@(!(foo)|bar).js", "packages/baz.js"));
        assert!(matches("packages/!(!(foo)).js", "packages/foo.js"));

        // fillNegs clones and re-lowers the suffix. Reusing the root's
        // non-empty star annotation here would falsely accept `a`.
        assert!(!matches("packages/!(a)@(*)", "packages/a"));
        assert!(!matches("packages/!(a)@(*)", "packages/ac"));
        assert!(matches("packages/!(a)@(*)", "packages/b"));
        assert!(!matches("packages/!(a)@(*|b)", "packages/a"));

        // A suffix negative cloned into an earlier negative's lookahead loses
        // minimatch's empty-ext marker and must keep its own suffix-aware
        // lookahead. Its root occurrence still broadens to a non-empty star.
        assert!(matches("packages/!(a)!(a|)b", "packages/aab"));
        assert!(matches("packages/!(a)!(b|)b", "packages/abb"));
        assert!(matches("packages/!(a)!(@(a)|)b", "packages/aab"));
    }

    #[test]
    fn follows_npm_empty_extglob_and_dot_boundaries() {
        assert!(matches("packages/!()", "packages/a"));
        assert!(matches("packages/!(a|)", "packages/a"));
        assert!(!matches("packages/!(a|)", "packages/.a"));
        assert!(!matches("packages/!(|a)", "packages/a"));
        assert!(matches("packages/!(|a)", "packages/b"));
        assert!(matches("packages/@(a|)", "packages/a"));
        assert!(matches("packages/@()", "packages/@()"));
        assert!(!matches("packages/@()", "packages/a"));

        // When an all-empty extglob is structurally start/end only because a
        // negative precedes it, minimatch exposes its raw regexp source. `@()`
        // accepts the literal `@`; the other operators quantify the preceding
        // negative and are language-equivalent on non-empty components.
        assert!(matches("packages/!(a)@()", "packages/b@"));
        assert!(matches("packages/!(a)@()", "packages/a@"));
        assert!(!matches("packages/!(a)@()", "packages/b@()"));
        for pattern in ["packages/!(a)?()", "packages/!(a)+()", "packages/!(a)*()"] {
            assert!(!matches(pattern, "packages/a"));
            assert!(matches(pattern, "packages/b"));
            assert!(matches(pattern, "packages/aa"));
            assert!(!matches(pattern, "packages/.y"));
        }
        assert!(matches("packages/@(@()|b)", "packages/@"));
        assert!(matches("packages/@(@()|b)", "packages/b"));
        assert!(!matches("packages/@(@()|b)", "packages/@()"));
        for pattern in ["packages/@(?())", "packages/@(+())", "packages/@(*())"] {
            assert!(NpmMinimatch::compile(pattern).is_err());
        }

        assert!(!matches("packages/@(.x|*)", "packages/.y"));
        assert!(matches("packages/@(.x|*)", "packages/.x"));
        assert!(matches("packages/?(a)@(*)", "packages/.y"));
        assert!(matches("packages/*(a)@(*)", "packages/.y"));
        assert!(matches("packages/@(a|)*", "packages/.y"));
        assert!(matches("packages/+(a|)*", "packages/.y"));
        assert!(!matches("packages/!(a)*", "packages/.y"));

        // A negative remains structurally at component start after preceding
        // negatives. Its dot guard therefore applies at every candidate split,
        // not just offset zero.
        assert!(!matches("packages/!()!()", "packages/x."));
        assert!(!matches("packages/!()!()", "packages/x.."));
        assert!(matches("packages/!()!()", "packages/xy"));
        assert!(matches("packages/!()!()", "packages/x.y"));
        assert!(!matches("packages/!(a|)!()", "packages/x."));
        assert!(!matches("packages/!(a|)!(b|)", "packages/x."));
        assert!(!matches("packages/!(a|)!(@())", "packages/x."));
        assert!(!matches("packages/!()@(*)", "packages/a."));
        assert!(!matches("packages/!()+(*)", "packages/a."));
        assert!(matches("packages/+(*)", "packages/a."));
        assert!(!matches("packages/+(*)", "packages/.a"));

        // A nullable first round of a leading zero-or-more extglob can move
        // into minimatch's non-start continuation, where a wildcard may then
        // consume a leading dot.
        assert!(matches("packages/*(?(*)|b)", "packages/.a"));
        assert!(matches("packages/*(*(*)|b)", "packages/.a"));
        assert!(matches("packages/*(*(?|*)|b)", "packages/.a"));

        // npm clones repeated bodies. A nested empty @() accepts `@` in the
        // first body but literal `@()` in the clone; reject this narrow family
        // rather than reuse one language and produce false workspace proofs.
        for pattern in ["packages/+(@())", "packages/*(a|@())"] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("repeated extglobs containing nested empty @()"));
        }
    }

    #[test]
    fn follows_component_local_utf16_and_unicode_regexp_modes() {
        // Without a Unicode POSIX class, JavaScript regexps consume UTF-16
        // code units. Astral literals still span both units, while `?` and a
        // character class consume one unit at a time.
        assert!(matches("packages/😀", "packages/😀"));
        assert!(matches("packages/@(😀)", "packages/😀"));
        assert!(!matches("packages/?", "packages/😀"));
        assert!(matches("packages/??", "packages/😀"));
        assert!(!matches("packages/@(?)", "packages/😀"));
        assert!(!matches("packages/[𐀀]", "packages/𐀀"));
        assert!(!matches("packages/[!𐀀]", "packages/𐀀"));
        assert!(matches("packages/*[𐀀]", "packages/𐀀"));

        // A Unicode-requiring POSIX class switches only its own component to
        // scalar `/u` semantics. Other components retain UTF-16 width.
        assert!(matches("packages/@(?|[[:alpha:]])", "packages/😀"));
        assert!(matches("packages/@([𐀀]|[[:digit:]])", "packages/𐀀"));
        assert!(!matches("packages/[[:alpha:]]/?", "packages/a/😀"));
        assert!(matches("packages/[[:alpha:]]/??", "packages/a/😀"));
        assert!(!matches("packages/{[😀],[[:alpha:]]}", "packages/😀"));
        assert!(matches("packages/!(?)", "packages/😀"));
        assert!(!matches("packages/!(?|[[:alpha:]])", "packages/😀"));

        for pattern in [
            "packages/[𐀀-𐀂]",
            "packages/[!a😀-a]?",
            "packages/@([a-😀]|[[:digit:]])",
            "packages/@([😀-\u{e000}]|[[:digit:]])",
        ] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("non-BMP characters with hyphens"), "{error}");
        }
        assert!(!matches("packages/[a-[:alpha:]]", "packages/a"));
        assert!(matches("packages/[!a[:graph:]]", "packages/b"));
        assert!(matches("packages/[.-.]x", "packages/.x"));
        assert!(matches("packages/[a[:graph:]][[:alpha:]]", "packages/.x"));
        assert!(matches("packages/[!a[:graph:]][[:alpha:]]", "packages/.x"));
    }

    #[test]
    fn rejects_minimatch_invalid_unicode_escapes_and_empty_quantifiers() {
        for pattern in [
            "packages/@(-|[[:alpha:]])",
            "packages/@(,|[[:alpha:]])",
            "packages/@(#|[[:alpha:]])",
            "packages/@( |[[:alpha:]])",
            "packages/@([-]|[[:alpha:]])",
            "packages/@([---]|[[:alpha:]])",
        ] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("invalid under minimatch's Unicode regular-expression rules"));
        }

        assert!(matches("packages/@([a-]|[[:alpha:]])", "packages/-"));
        assert!(matches("packages/@(-|[[:ascii:]])", "packages/-"));
        assert!(matches("packages/[[:alpha:]]/-", "packages/a/-"));
        for line_terminator in ['\n', '\r', '\u{2028}', '\u{2029}'] {
            let pattern = format!("packages/@([{line_terminator}]|[[:alpha:]])");
            let candidate = format!("packages/{line_terminator}");
            assert!(NpmMinimatch::compile(&pattern).is_ok(), "{pattern:?}");
            assert!(matches(&pattern, &candidate), "{pattern:?}");

            let invalid_literal = format!("packages/@({line_terminator}|[[:alpha:]])");
            let error = NpmMinimatch::compile(&invalid_literal).unwrap_err();
            assert!(error.contains("invalid under minimatch's Unicode regular-expression rules"));
        }

        for broad_negative in ["!()", "!(a|)", "!(@(a))"] {
            for empty_operator in ['?', '+', '*'] {
                for pattern in [
                    format!("packages/{broad_negative}{empty_operator}()"),
                    format!("packages/@({broad_negative}{empty_operator}())"),
                ] {
                    let error = NpmMinimatch::compile(&pattern).unwrap_err();
                    assert!(
                        error.contains("invalid minimatch regular expression"),
                        "{pattern}: {error}"
                    );
                }
            }
        }
        for pattern in ["packages/!(a)!()?()", "packages/@(!(a)!()?())"] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("invalid minimatch regular expression"));
        }

        for empty_operator in ['?', '+', '*'] {
            for pattern in [
                format!("packages/!(a){empty_operator}()"),
                format!("packages/@(!(a){empty_operator}())"),
                format!("packages/!()!(a){empty_operator}()"),
                format!("packages/@(!()!(a){empty_operator}())"),
            ] {
                assert!(NpmMinimatch::compile(&pattern).is_ok(), "{pattern}");
            }
        }
    }

    #[test]
    fn matches_checked_in_npm11_differential_corpus() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/npm-minimatch/npm11-vectors.json"
        ))
        .expect("decode npm minimatch oracle corpus");
        assert_eq!(corpus["oracle"]["npm"], "11.0.0");
        assert_eq!(corpus["oracle"]["minimatch"], "9.0.5");
        assert_eq!(corpus["oracle"]["unicode"], "16.0");
        assert_eq!(unicode_general_category::UNICODE_VERSION, (16, 0, 0));
        let candidates = corpus["candidates"]
            .as_array()
            .expect("oracle candidate array");
        let cases = corpus["cases"].as_array().expect("oracle case array");
        let pairs = corpus["pairs"].as_array().expect("oracle pair array");
        assert_eq!(candidates.len() * cases.len() + pairs.len(), 1_794);

        for case in cases {
            let pattern = case["pattern"].as_str().expect("oracle pattern");
            let expected = case["matches"]
                .as_array()
                .expect("oracle match array")
                .iter()
                .map(|candidate| candidate.as_str().expect("oracle match candidate"))
                .collect::<BTreeSet<_>>();
            let matcher = NpmMinimatch::compile(pattern)
                .unwrap_or_else(|error| panic!("oracle pattern {pattern:?} failed: {error}"));
            for candidate in candidates {
                let candidate = candidate.as_str().expect("oracle candidate");
                let actual = matcher.is_match(candidate).unwrap_or_else(|error| {
                    panic!("oracle match {pattern:?} against {candidate:?} failed: {error}")
                });
                assert_eq!(
                    actual,
                    expected.contains(candidate),
                    "npm 11 mismatch for {pattern:?} against {candidate:?}"
                );
            }
        }

        for pair in pairs {
            let pattern = pair["pattern"].as_str().expect("pair pattern");
            let candidate = pair["candidate"].as_str().expect("pair candidate");
            let expected = pair["matches"].as_bool().expect("pair expectation");
            let actual = NpmMinimatch::compile(pattern)
                .unwrap_or_else(|error| panic!("oracle pair {pattern:?} failed: {error}"))
                .is_match(candidate)
                .unwrap_or_else(|error| {
                    panic!("oracle pair {pattern:?} against {candidate:?} failed: {error}")
                });
            assert_eq!(
                actual, expected,
                "npm 11 pair mismatch for {pattern:?} against {candidate:?}"
            );
        }

        for rejection in corpus["rejects"].as_array().expect("oracle reject array") {
            let pattern = rejection["pattern"].as_str().expect("rejected pattern");
            let expected = rejection["contains"].as_str().expect("rejection text");
            rejection["npmThrows"]
                .as_bool()
                .expect("npm rejection classification");
            let error = NpmMinimatch::compile(pattern)
                .expect_err("oracle rejection must fail closed during compilation");
            assert!(
                error.contains(expected),
                "rejection {pattern:?} returned {error:?}"
            );
        }
    }

    #[test]
    fn treats_dollar_and_singleton_braces_as_literals() {
        assert!(matches("packages/$", "packages/$"));
        assert!(!matches("packages/$", "packages/x"));
        assert!(matches("packages/(core)", "packages/(core)"));
    }

    #[test]
    fn recognizes_comments_only_at_the_start_of_the_whole_pattern() {
        let comment = NpmMinimatch::compile("# packages/*").unwrap();
        assert!(!comment.is_match("# packages/api").unwrap());
        assert!(matches("packages/#name", "packages/#name"));
    }

    #[test]
    fn follows_minimatch_literal_fallbacks_and_rejects_unsafe_input() {
        assert!(NpmMinimatch::compile("").is_err());
        assert!(NpmMinimatch::compile("packages\\*").is_err());
        assert!(matches("packages/[abc", "packages/[abc"));
        assert!(matches("packages/{a,b", "packages/{a,b"));
        for pattern in [
            "packages/@(a|b",
            "packages/!(a|b",
            "packages/?(",
            "packages/*(",
        ] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("unmatched npm workspace extglob openers"));
        }
        assert!(matches("packages/a(b)", "packages/a(b)"));
        assert!(matches("packages/?x", "packages/ax"));
        assert!(matches("packages/*x", "packages/anythingx"));
        assert!(matches("packages/@x", "packages/@x"));
        assert!(matches("packages/+x", "packages/+x"));
        assert!(matches("packages/!x", "packages/!x"));
        assert!(matches("packages/a)", "packages/a)"));
        assert!(matches("packages/[]", "packages/[]"));
        assert!(matches("packages/[!]", "packages/[!]"));
        assert!(matches("packages/[]]", "packages/]"));
        assert!(!matches("packages/[z-a]", "packages/z"));
        assert!(!matches("packages/[!z-a]", "packages/z"));
        assert!(matches("packages/[z-aq]", "packages/q"));
        assert!(matches("packages//api", "packages/api"));

        let matcher = NpmMinimatch::compile("packages/*").unwrap();
        assert!(matcher.is_match("packages//api").is_err());
        assert!(matcher.is_match("packages/../api").is_err());
        assert!(matcher.is_match(&"x".repeat(4_097)).is_err());
    }

    #[test]
    fn exposes_the_workspace_collection_limit_to_the_caller() {
        assert_eq!(MAX_WORKSPACE_PATTERNS, 256);
    }

    #[test]
    fn preserves_resource_bounds_after_extglob_lowering() {
        let clone_heavy = format!("packages/{}", "!(a|b)".repeat(7));
        let compile_error = NpmMinimatch::compile(&clone_heavy).unwrap_err();
        assert!(compile_error.contains("4096-node syntax limit after extglob lowering"));

        let matcher = NpmMinimatch::compile("packages/+(*|*)").unwrap();
        let candidate = format!("packages/{}", "x".repeat(512));
        let match_error = matcher.is_match(&candidate).unwrap_err();
        assert!(match_error.contains("250000-operation limit"));
    }
}
