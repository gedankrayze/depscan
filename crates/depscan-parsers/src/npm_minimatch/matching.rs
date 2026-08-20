use super::*;

pub(super) fn end_token_positions(
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
    pub(super) fn mark_copied_negative_suffix(&mut self) {
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

    pub(super) fn requires_unicode_regexp(&self) -> bool {
        match self {
            Self::Class(class) => class.requires_unicode_regexp(),
            Self::Extglob { alternatives, .. } => {
                alternatives.iter().any(Sequence::requires_unicode_regexp)
            }
            Self::Literal(_) | Self::LiteralText(_) | Self::AnyChar | Self::Star { .. } => false,
        }
    }

    pub(super) fn contains_invalid_unicode_identity_escape(&self) -> bool {
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

    pub(super) fn end_positions(
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

    pub(super) fn explicitly_starts_with_dot(&self) -> bool {
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

    pub(super) fn can_defer_leading_dot(&self) -> bool {
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

    pub(super) fn is_nullable(&self) -> bool {
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

pub(super) fn match_literal_character(
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

pub(super) fn extend_alternative_positions(
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

pub(super) fn negative_lookahead_matches(
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

pub(super) fn extend_repeated_positions(
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
