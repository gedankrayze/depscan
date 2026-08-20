use super::*;

pub(super) struct ComponentParser<'a> {
    chars: Vec<char>,
    position: usize,
    nesting: usize,
    node_count: &'a mut usize,
}

impl<'a> ComponentParser<'a> {
    pub(super) fn new(component: &str, node_count: &'a mut usize) -> Self {
        Self {
            chars: component.chars().collect(),
            position: 0,
            nesting: 0,
            node_count,
        }
    }

    pub(super) fn parse_top_level(&mut self) -> Result<Sequence, String> {
        let sequence = self.parse_sequence(false)?;
        if self.position != self.chars.len() {
            return Err("npm workspace pattern contains an unexpected delimiter".to_owned());
        }
        Ok(sequence)
    }

    pub(super) fn parse_sequence(&mut self, inside_extglob: bool) -> Result<Sequence, String> {
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

    pub(super) fn extglob_is_closed(&self, start: usize) -> bool {
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

    pub(super) fn class_is_closed(&self, start: usize) -> bool {
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

    pub(super) fn parse_extglob(&mut self, operator: char) -> Result<Token, String> {
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

    pub(super) fn parse_class(&mut self) -> Result<Token, String> {
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

    pub(super) fn add_node(&mut self) -> Result<(), String> {
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
pub(super) enum ClassPiece {
    Character(char),
    Posix(PosixClass),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Utf16ClassPiece {
    Unit(u16),
    Posix(PosixClass),
}

pub(super) fn compile_character_class_items(
    pieces: &[ClassPiece],
) -> (Vec<ClassItem>, Vec<ClassItem>) {
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

pub(super) fn decode_unicode_class_items(utf16_items: &[ClassItem]) -> Vec<ClassItem> {
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
