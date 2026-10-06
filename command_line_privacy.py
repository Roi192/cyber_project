# ==================================================
# STEP 25A: COMMAND-LINE PRIVACY / REDACTION
# ==================================================
#
# Deliberately NOT a full command-line parser (explicit instruction) -
# a best-effort, conservative pattern match over a fixed list of
# sensitive flag/key names. "Conservative" means: when there is any
# ambiguity about whether something is a secret, this module redacts
# rather than guesses it is safe - the opposite failure (leaking a real
# secret because the pattern almost-but-not-quite matched) is the one
# this module is built to avoid, even at the cost of occasionally
# redacting a harmless value that merely LOOKS like a secret flag.
#
# Used on BOTH sides, reusing the exact same function (never two
# divergent implementations): the Agent redacts before sending, and the
# server (process_events.py) re-applies this same function defensively
# on receipt - belt-and-suspenders, not a new mechanism.
#
# Scope: redacts the VALUE that follows a small, fixed list of
# known-sensitive flag/key names, in either of two common forms:
#   --password=value          (inline, '=' or ':' separator, 0-2 leading dashes)
#   --password value          (the value is the NEXT token)
# and a bare "key=value"/"key:value" token with no leading dashes at
# all (e.g. a connection-string-style argument). Never reads file
# contents, never attempts to decode base64/encoded blobs, never tries
# to recognize every possible CLI convention in existence.
# ==================================================

import re

REDACTED_MARKER = "***REDACTED***"

# Fixed, explicit list - never inferred/learned. Matched case-
# insensitively. Add to this list deliberately, not automatically.
SENSITIVE_KEY_NAMES = (
    "password",
    "passwd",
    "pwd",
    "token",
    "api-key",
    "apikey",
    "api_key",
    "secret",
    "authorization",
    "auth",
)

_INLINE_PATTERN = re.compile(
    r'^(?P<prefix>-{0,2}(?:' + "|".join(re.escape(k) for k in SENSITIVE_KEY_NAMES) + r'))'
    r'(?P<sep>[=:])(?P<value>.*)$',
    re.IGNORECASE,
)

_BARE_FLAG_PATTERN = re.compile(
    r'^-{1,2}(?:' + "|".join(re.escape(k) for k in SENSITIVE_KEY_NAMES) + r')$',
    re.IGNORECASE,
)


def redact_command_line(command_line):
    """
    command_line: a str, or a list of argv-style tokens (as
    psutil.Process.cmdline() returns). Returns (redacted_string,
    was_redacted). redacted_string is always a single str (tokens
    re-joined with a single space) - the exact original token
    boundaries/quoting are NOT guaranteed to round-trip, which is
    acceptable since this is for ANALYST DISPLAY/forensics, never for
    re-executing the command.

    None in, None out, was_redacted=False - a missing command line is
    not an error here (the caller decides whether that itself is
    notable).
    """

    if command_line is None:
        return None, False

    if isinstance(command_line, (list, tuple)):
        tokens = [str(t) for t in command_line]
    else:
        tokens = str(command_line).split()

    if not tokens:
        return "", False

    result = []
    redacted_any = False
    i = 0

    while i < len(tokens):

        token = tokens[i]

        inline_match = _INLINE_PATTERN.match(token)

        if inline_match:
            result.append(f"{inline_match.group('prefix')}{inline_match.group('sep')}{REDACTED_MARKER}")
            redacted_any = True
            i += 1
            continue

        if _BARE_FLAG_PATTERN.match(token):
            result.append(token)
            if i + 1 < len(tokens):
                result.append(REDACTED_MARKER)
                redacted_any = True
                i += 2
                continue
            i += 1
            continue

        result.append(token)
        i += 1

    return " ".join(result), redacted_any
