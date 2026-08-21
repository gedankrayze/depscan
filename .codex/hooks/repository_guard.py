#!/usr/bin/env python3
"""Deny Git commands that bypass DepScan's permanent repository boundaries."""

from __future__ import annotations

import json
import re
import shlex
import sys
from collections.abc import Iterator, Sequence


RELEASE_TAG = re.compile(r"^(?:refs/tags/)?v[0-9].*")
FORCE_OPTIONS = {"-f", "--force", "--force-with-lease"}


def command_segments(command: str) -> Iterator[list[str]]:
    """Yield shell command segments without executing or expanding the input."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
    lexer.commenters = ""
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True

    segment: list[str] = []
    try:
        for token in lexer:
            if token and all(character in ";&|()\n" for character in token):
                if segment:
                    yield segment
                    segment = []
            else:
                segment.append(token)
    except ValueError:
        return

    if segment:
        yield segment


def git_arguments(segment: Sequence[str]) -> list[str] | None:
    """Return Git arguments when Git is the command being invoked."""
    command_index = 0
    while command_index < len(segment) and re.match(
        r"^[A-Za-z_][A-Za-z0-9_]*=", segment[command_index]
    ):
        command_index += 1
    if command_index < len(segment) and segment[command_index] == "command":
        command_index += 1
    if command_index >= len(segment) or command_name(segment[command_index]) != "git":
        return None
    return list(segment[command_index + 1 :])


def command_name(value: str) -> str:
    """Return a command basename without importing filesystem behavior."""
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def pushed_ref_targets_main(token: str) -> bool:
    normalized = token.lstrip("+")
    target = normalized.rsplit(":", 1)[-1]
    return target in {"main", "refs/heads/main"}


def release_tag_token(token: str) -> bool:
    return RELEASE_TAG.match(token.lstrip("+:")) is not None


def segment_denial(segment: Sequence[str]) -> str | None:
    arguments = git_arguments(segment)
    if not arguments:
        return None

    if "push" in arguments:
        push_index = arguments.index("push")
        push_arguments = arguments[push_index + 1 :]
        if any(
            option in FORCE_OPTIONS
            or option.startswith("--force=")
            or option.startswith("--force-with-lease=")
            or (option.startswith("-") and not option.startswith("--") and "f" in option[1:])
            for option in push_arguments
        ):
            return "Force-pushing is not allowed in this repository."
        positionals = [token for token in push_arguments if not token.startswith("-")]
        refspecs = positionals[1:] if positionals else []
        if any(pushed_ref_targets_main(token) for token in refspecs):
            return "Push through develop and a protected pull request; never push directly to main."
        if "--delete" in push_arguments and any(release_tag_token(token) for token in refspecs):
            return "Published release tags must not be deleted."
        if any(token.startswith(":") and release_tag_token(token) for token in refspecs):
            return "Published release tags must not be deleted."

    if "tag" in arguments:
        tag_index = arguments.index("tag")
        tag_arguments = arguments[tag_index + 1 :]
        has_release_tag = any(release_tag_token(token) for token in tag_arguments)
        if has_release_tag and any(option in {"-d", "--delete"} for option in tag_arguments):
            return "Published release tags must not be deleted."
        if has_release_tag and any(option in {"-f", "--force"} for option in tag_arguments):
            return "Published release tags must not be moved."

    return None


def denial_reason(command: str) -> str | None:
    for segment in command_segments(command):
        reason = segment_denial(segment)
        if reason is not None:
            return reason
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0

    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return 0

    reason = denial_reason(command)
    if reason is None:
        return 0

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
