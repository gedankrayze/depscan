use super::*;

/// Lower a parsed sequence into npm minimatch's placement-sensitive form.
/// Negative lookaheads receive owned copies of the exact suffix chain, which
/// mirrors minimatch's `fillNegs` pass and avoids reusing root-only `*` state.
#[allow(clippy::too_many_arguments)]
pub(super) fn lower_sequence(
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

pub(super) fn append_copied_negative_suffix(output: &mut Vec<Token>, suffix: &[Token]) {
    for token in suffix {
        let mut copied = token.clone();
        copied.mark_copied_negative_suffix();
        output.push(copied);
    }
}

pub(super) fn count_token_nodes(tokens: &[Token]) -> usize {
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

pub(super) fn add_compiled_nodes(node_count: &mut usize, amount: usize) -> Result<(), String> {
    *node_count = node_count.saturating_add(amount);
    if *node_count > MAX_AST_NODES {
        return Err(format!(
            "npm workspace pattern exceeds the {MAX_AST_NODES}-node syntax limit after extglob lowering"
        ));
    }
    Ok(())
}
