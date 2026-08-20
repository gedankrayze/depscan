use super::*;

impl PathPattern {
    pub(super) fn is_match(
        &self,
        candidate: &[&str],
        context: &mut MatchContext,
    ) -> Result<bool, String> {
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
    pub(super) fn is_match(
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

    pub(super) fn end_positions(
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

    pub(super) fn allows_leading_dot(&self) -> bool {
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

    pub(super) fn is_nullable(&self) -> bool {
        self.tokens.iter().all(Token::is_nullable)
    }

    pub(super) fn requires_unicode_regexp(&self) -> bool {
        self.tokens.iter().any(Token::requires_unicode_regexp)
    }

    pub(super) fn contains_invalid_unicode_identity_escape(&self) -> bool {
        self.tokens
            .iter()
            .any(Token::contains_invalid_unicode_identity_escape)
    }

    pub(super) fn validate_empty_quantifiers(&self) -> Result<(), String> {
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

    pub(super) fn validate_repeat_clone_sensitive_empty_exact(&self) -> Result<(), String> {
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

    pub(super) fn contains_empty_exact_extglob(&self) -> bool {
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
