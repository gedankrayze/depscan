use super::*;

impl CharacterClass {
    pub(super) fn matches(&self, candidate: u32, unit_mode: UnitMode) -> bool {
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

    pub(super) fn explicitly_includes(&self, candidate: char) -> bool {
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

    pub(super) fn requires_unicode_regexp(&self) -> bool {
        self.unicode_items
            .iter()
            .any(|item| matches!(item, ClassItem::Posix(class) if class.requires_unicode_regexp()))
    }

    pub(super) fn contains_invalid_unicode_identity_escape(&self) -> bool {
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

pub(super) fn is_javascript_dot_line_terminator(value: u32) -> bool {
    matches!(value, 0x000a | 0x000d | 0x2028 | 0x2029)
}

pub(super) fn is_invalid_unicode_identity_escape(value: u32) -> bool {
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
    pub(super) fn matches(&self, candidate: u32) -> bool {
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
    pub(super) fn parse(name: &str) -> Result<Self, String> {
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

    pub(super) fn matches(self, candidate: char) -> bool {
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

    pub(super) fn requires_unicode_regexp(self) -> bool {
        !matches!(self, Self::Ascii | Self::Xdigit)
    }
}

pub(super) fn is_unicode_letter(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::LowercaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::UppercaseLetter
    )
}

pub(super) fn is_unicode_separator(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
    )
}

pub(super) fn is_unicode_other(category: GeneralCategory) -> bool {
    matches!(
        category,
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::PrivateUse
            | GeneralCategory::Surrogate
            | GeneralCategory::Unassigned
    )
}

pub(super) fn is_unicode_punctuation(category: GeneralCategory) -> bool {
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
