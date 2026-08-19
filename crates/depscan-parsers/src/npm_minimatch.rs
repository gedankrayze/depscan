//! A bounded subset of npm's `minimatch` syntax for workspace paths.
//!
//! The parser deliberately has no filesystem behavior. It compiles one
//! normalized, positive workspace pattern and matches normalized package-map
//! keys. Negation ordering and path separator normalization remain the
//! caller's responsibility.
//!
//! npm's common workspace syntax is supported, but two ambiguous constructions
//! are rejected explicitly: extglob alternatives cannot contain `/`, and a
//! negative extglob must occupy a whole component without extglob nesting. The
//! latter is important because npm 11's bundled minimatch applies non-local
//! lookahead rules and broadens some nested forms to a wildcard.
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
    Pattern(Sequence),
}

#[derive(Debug, Clone)]
struct Sequence {
    tokens: Vec<Token>,
}

#[derive(Debug, Clone)]
enum Token {
    Literal(char),
    AnyChar,
    Star,
    Class(CharacterClass),
    Extglob {
        kind: ExtglobKind,
        alternatives: Vec<Sequence>,
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
    items: Vec<ClassItem>,
}

#[derive(Debug, Clone)]
enum ClassItem {
    Character(char),
    Range(char, char),
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

    let mut components = Vec::with_capacity(raw_components.len());
    for component in raw_components {
        if component == "**" {
            if !matches!(components.last(), Some(PathComponent::GlobStar)) {
                components.push(PathComponent::GlobStar);
            }
            continue;
        }
        let mut parser = ComponentParser::new(component, node_count);
        let sequence = parser.parse_top_level()?;
        components.push(PathComponent::Pattern(sequence));
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
                PathComponent::Pattern(pattern) => {
                    for (start, active) in states.iter().copied().enumerate() {
                        if !active || start == candidate.len() {
                            continue;
                        }
                        context.bump(1)?;
                        if pattern.is_match(candidate[start], context)? {
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
    fn is_match(&self, candidate: &str, context: &mut MatchContext) -> Result<bool, String> {
        let chars = candidate.chars().collect::<Vec<_>>();
        if chars.first() == Some(&'.') && !self.allows_leading_dot() {
            return Ok(false);
        }
        Ok(self
            .end_positions(&chars, vec![0], chars.len(), context)?
            .contains(&chars.len()))
    }

    fn end_positions(
        &self,
        chars: &[char],
        mut positions: Vec<usize>,
        ceiling: usize,
        context: &mut MatchContext,
    ) -> Result<Vec<usize>, String> {
        for token in &self.tokens {
            let mut next = Vec::new();
            for position in positions {
                context.bump(1)?;
                token.end_positions(chars, position, ceiling, context, &mut next)?;
            }
            positions = deduplicate_positions(next, ceiling);
            if positions.is_empty() {
                break;
            }
        }
        Ok(positions)
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
}

impl Token {
    fn contains_extglob(&self) -> bool {
        matches!(self, Self::Extglob { .. })
    }

    fn contains_standalone_star(&self) -> bool {
        match self {
            Self::Star => true,
            Self::Extglob { alternatives, .. } => alternatives.iter().any(|alternative| {
                alternative
                    .tokens
                    .iter()
                    .any(Self::contains_standalone_star)
            }),
            Self::Literal(_) | Self::AnyChar | Self::Class(_) => false,
        }
    }

    fn is_negative_extglob(&self) -> bool {
        matches!(
            self,
            Self::Extglob {
                kind: ExtglobKind::Negated,
                ..
            }
        )
    }

    fn end_positions(
        &self,
        chars: &[char],
        position: usize,
        ceiling: usize,
        context: &mut MatchContext,
        output: &mut Vec<usize>,
    ) -> Result<(), String> {
        match self {
            Self::Literal(expected) => {
                if position < ceiling && chars[position] == *expected {
                    output.push(position + 1);
                }
            }
            Self::AnyChar => {
                if position < ceiling {
                    output.push(position + 1);
                }
            }
            Self::Star => {
                for end in position..=ceiling {
                    context.bump(1)?;
                    output.push(end);
                }
            }
            Self::Class(class) => {
                if position < ceiling && class.matches(chars[position]) {
                    output.push(position + 1);
                }
            }
            Self::Extglob { kind, alternatives } => match kind {
                ExtglobKind::ExactlyOne => {
                    extend_alternative_positions(
                        alternatives,
                        chars,
                        position,
                        ceiling,
                        context,
                        output,
                    )?;
                }
                ExtglobKind::ZeroOrOne => {
                    output.push(position);
                    extend_alternative_positions(
                        alternatives,
                        chars,
                        position,
                        ceiling,
                        context,
                        output,
                    )?;
                }
                ExtglobKind::OneOrMore => {
                    extend_repeated_positions(
                        alternatives,
                        chars,
                        position,
                        ceiling,
                        false,
                        context,
                        output,
                    )?;
                }
                ExtglobKind::ZeroOrMore => {
                    extend_repeated_positions(
                        alternatives,
                        chars,
                        position,
                        ceiling,
                        true,
                        context,
                        output,
                    )?;
                }
                ExtglobKind::Negated => {
                    let mut excluded = Vec::new();
                    extend_alternative_positions(
                        alternatives,
                        chars,
                        position,
                        ceiling,
                        context,
                        &mut excluded,
                    )?;
                    let excluded = position_set(&excluded, ceiling);
                    for (end, is_excluded) in excluded
                        .iter()
                        .copied()
                        .enumerate()
                        .take(ceiling + 1)
                        .skip(position)
                    {
                        context.bump(1)?;
                        if !is_excluded {
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
            Self::Class(class) => class.explicitly_includes('.'),
            Self::Extglob {
                kind:
                    ExtglobKind::ExactlyOne
                    | ExtglobKind::ZeroOrOne
                    | ExtglobKind::OneOrMore
                    | ExtglobKind::ZeroOrMore,
                alternatives,
            } => alternatives.iter().any(Sequence::allows_leading_dot),
            Self::AnyChar
            | Self::Star
            | Self::Extglob {
                kind: ExtglobKind::Negated,
                ..
            } => false,
        }
    }

    fn can_defer_leading_dot(&self) -> bool {
        match self {
            // A bare wildcard at the beginning still activates minimatch's
            // dot guard even though `*` can consume an empty string.
            Self::Star => false,
            Self::Extglob {
                kind: ExtglobKind::ZeroOrOne | ExtglobKind::ZeroOrMore,
                ..
            } => true,
            Self::Extglob {
                kind: ExtglobKind::ExactlyOne | ExtglobKind::OneOrMore,
                alternatives,
            } => alternatives.iter().any(Sequence::is_nullable),
            Self::Literal(_)
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
            Self::Star => true,
            Self::Extglob {
                kind: ExtglobKind::ZeroOrOne | ExtglobKind::ZeroOrMore,
                ..
            } => true,
            Self::Extglob {
                kind: ExtglobKind::ExactlyOne | ExtglobKind::OneOrMore,
                alternatives,
            } => alternatives.iter().any(Sequence::is_nullable),
            Self::Extglob {
                kind: ExtglobKind::Negated,
                alternatives,
            } => !alternatives.iter().any(Sequence::is_nullable),
            Self::Literal(_) | Self::AnyChar | Self::Class(_) => false,
        }
    }
}

fn extend_alternative_positions(
    alternatives: &[Sequence],
    chars: &[char],
    position: usize,
    ceiling: usize,
    context: &mut MatchContext,
    output: &mut Vec<usize>,
) -> Result<(), String> {
    for alternative in alternatives {
        context.bump(1)?;
        output.extend(alternative.end_positions(chars, vec![position], ceiling, context)?);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn extend_repeated_positions(
    alternatives: &[Sequence],
    chars: &[char],
    position: usize,
    ceiling: usize,
    include_zero: bool,
    context: &mut MatchContext,
    output: &mut Vec<usize>,
) -> Result<(), String> {
    let mut seen = vec![false; ceiling + 1];
    let mut frontier = vec![position];
    if include_zero {
        seen[position] = true;
        output.push(position);
    }

    let mut first_round = true;
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for start in frontier {
            let mut ends = Vec::new();
            extend_alternative_positions(alternatives, chars, start, ceiling, context, &mut ends)?;
            for end in ends {
                context.bump(1)?;
                if !seen[end] {
                    seen[end] = true;
                    output.push(end);
                    next.push(end);
                } else if first_round && !include_zero && end == position {
                    // One nullable alternative is still one occurrence.
                    output.push(end);
                }
            }
        }
        first_round = false;
        frontier = next;
    }
    Ok(())
}

impl CharacterClass {
    fn matches(&self, candidate: char) -> bool {
        if self.items.is_empty() {
            return false;
        }
        let contains = self.items.iter().any(|item| item.matches(candidate));
        contains != self.negated
    }

    fn explicitly_includes(&self, candidate: char) -> bool {
        !self.negated
            && matches!(
                self.items.as_slice(),
                [ClassItem::Character(value)] if *value == candidate
            )
    }
}

impl ClassItem {
    fn matches(&self, candidate: char) -> bool {
        match self {
            Self::Character(value) => candidate == *value,
            Self::Range(start, end) => (*start..=*end).contains(&candidate),
            Self::Posix(class) => class.matches(candidate),
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
        if sequence.tokens.iter().any(Token::contains_standalone_star)
            && sequence.tokens.iter().any(Token::contains_extglob)
        {
            return Err(
                "standalone wildcards combined with npm workspace extglobs are not safely supported"
                    .to_owned(),
            );
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
            if matches!(current, '@' | '?' | '+' | '*' | '!')
                && next == Some('(')
                && self.extglob_is_closed(self.position)
            {
                tokens.push(self.parse_extglob(current)?);
                continue;
            }
            let token = match current {
                '*' => {
                    self.position += 1;
                    if matches!(tokens.last(), Some(Token::Star)) {
                        continue;
                    }
                    Token::Star
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
        if tokens.len() > 1 && tokens.iter().any(Token::is_negative_extglob) {
            return Err(
                "negative npm workspace extglobs must occupy an entire path component".to_owned(),
            );
        }
        Ok(Sequence { tokens })
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
        self.nesting += 1;
        if self.nesting > MAX_NESTING {
            return Err(format!(
                "npm workspace extglob exceeds the {MAX_NESTING}-level nesting limit"
            ));
        }
        if operator == '!' && self.nesting > 1 {
            return Err("nested negative npm workspace extglobs are not supported".to_owned());
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
        if operator == '!'
            && alternatives
                .iter()
                .any(|alternative| alternative.tokens.is_empty())
        {
            return Err(
                "negative npm workspace extglobs must not contain empty alternatives".to_owned(),
            );
        }
        if operator == '!'
            && alternatives
                .iter()
                .any(|alternative| alternative.tokens.iter().any(Token::contains_extglob))
        {
            return Err(
                "nested extglobs inside a negative npm workspace extglob are not supported"
                    .to_owned(),
            );
        }
        self.add_node()?;
        let kind = match operator {
            '@' => ExtglobKind::ExactlyOne,
            '?' => ExtglobKind::ZeroOrOne,
            '+' => ExtglobKind::OneOrMore,
            '*' => ExtglobKind::ZeroOrMore,
            '!' => ExtglobKind::Negated,
            _ => unreachable!("caller recognizes extglob operators"),
        };
        Ok(Token::Extglob { kind, alternatives })
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

        let mut items = Vec::new();
        let mut index = 0usize;
        while index < pieces.len() {
            if index + 2 < pieces.len()
                && let (
                    ClassPiece::Character(start),
                    ClassPiece::Character('-'),
                    ClassPiece::Character(end),
                ) = (&pieces[index], &pieces[index + 1], &pieces[index + 2])
            {
                if start > end {
                    index += 3;
                    continue;
                }
                items.push(ClassItem::Range(*start, *end));
                index += 3;
                continue;
            }
            items.push(match pieces[index] {
                ClassPiece::Character(value) => ClassItem::Character(value),
                ClassPiece::Posix(value) => ClassItem::Posix(value),
            });
            index += 1;
        }
        self.add_node()?;
        Ok(Token::Class(CharacterClass { negated, items }))
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
    let mut in_class = false;
    for (index, current) in chars.iter().copied().enumerate() {
        match current {
            '[' => in_class = true,
            ']' => in_class = false,
            '{' if !in_class => {
                if stack.len() >= MAX_NESTING {
                    return Err(format!(
                        "npm workspace brace expression exceeds the {MAX_NESTING}-level nesting limit"
                    ));
                }
                stack.push(index);
            }
            '}' if !in_class => {
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
    let mut parentheses = 0usize;
    let mut in_class = false;
    for (index, current) in chars.iter().copied().enumerate() {
        match current {
            '[' => in_class = true,
            ']' => in_class = false,
            '{' if !in_class => braces += 1,
            '}' if !in_class => braces = braces.saturating_sub(1),
            '(' if !in_class => parentheses += 1,
            ')' if !in_class => parentheses = parentheses.saturating_sub(1),
            value if value == delimiter && !in_class && braces == 0 && parentheses == 0 => {
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

fn position_set(positions: &[usize], ceiling: usize) -> Vec<bool> {
    let mut set = vec![false; ceiling + 1];
    for position in positions {
        set[*position] = true;
    }
    set
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

        // Negative extglobs use non-local lookahead in minimatch. Whole path
        // components are implemented exactly; combinations are rejected so a
        // locally plausible match cannot falsely prove workspace identity.
        let suffixed_negative = NpmMinimatch::compile("packages/pre!(bad).js").unwrap_err();
        assert!(suffixed_negative.contains("must occupy an entire path component"));
        let trailing_wildcard = NpmMinimatch::compile("packages/!(a)*").unwrap_err();
        assert!(trailing_wildcard.contains("must occupy an entire path component"));
        let empty_negative = NpmMinimatch::compile("packages/!(a|)").unwrap_err();
        assert!(empty_negative.contains("must not contain empty alternatives"));

        // npm minimatch treats a slash inside an extglob as a path-component
        // split that can never match the intended alternatives. Rejecting it
        // makes that unsupported construction visible to the caller.
        let cross_component = NpmMinimatch::compile("@(packages/a|packages/b)").unwrap_err();
        assert!(cross_component.contains("must not cross path separators"));

        // npm 11's bundled minimatch rewrites this nested-negative form into
        // a broad wildcard. That is not safe for proving workspace identity.
        let nested_negative = NpmMinimatch::compile("packages/!(@(foo|bar)).js").unwrap_err();
        assert!(nested_negative.contains("nested extglobs inside a negative"));

        // minimatch makes a standalone `*` non-nullable beside an extglob.
        // Reject the combination until the matcher carries the required
        // suffix-aware state instead of broadening it into a workspace proof.
        for pattern in [
            "packages/*@(a|b)",
            "packages/@(a|b)*",
            "packages/*+(a|b)",
            "packages/+(a|b)*",
            "packages/@(a*|b)",
        ] {
            let error = NpmMinimatch::compile(pattern).unwrap_err();
            assert!(error.contains("standalone wildcards combined"));
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
        assert!(matches("packages/@(a|b", "packages/@(a|b"));
        assert!(matches("packages/!(a|b", "packages/!(a|b"));
        assert!(matches("packages/?(", "packages/a("));
        assert!(matches("packages/*(", "packages/anything("));
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
}
