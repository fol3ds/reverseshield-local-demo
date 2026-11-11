"""Create a shareable JSON copy; never modify the original static evidence.

Structured measurements survive. Raw tool output, commands, environment and
decompiled bodies are omitted by default because regex cannot identify every
secret. This is a sharing control, not a general-purpose DLP classifier.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

PRIVATE_FIELDS = {'key', 'rs_key', 'token', 'api_token', 'password', 'secret',
                  'authorization', 'environment', 'env', 'command', 'commands',
                  'argv', 'output', 'stdout', 'stderr', 'pseudocode', 'decompiled',
                  'code', 'body', 'artifacts', 'events', 'strings', 'error',
                  'message', 'warnings', 'filename', 'label', 'name', 'section_names',
                  'api_key', 'access_token', 'refresh_token', 'private_key', 'credentials'}
HOME_USER = re.compile(r'(?:[A-Za-z]:[\\/]Users[\\/]|/(?:home|Users)/)([^\\/\s"<>]+)', re.I)
PATH = re.compile(r'(?:[A-Za-z]:[\\/]|\\\\|(?<![\w:])/(?!/))[^\r\n"<>|]*')
SECRET = re.compile(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b', re.S)
EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
KEY_LITERAL = re.compile(r'0x9e3779b9|\brs_key\s*=\s*[^;\s]+', re.I)


def sanitize_report(report):
    """Return an independent redacted structure; hashes/counts remain intact."""
    # Work on actual strings (JSON escaping would hide Windows home paths).
    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for k, v in value.items():
                yield str(k)
                yield from strings(v)
        elif isinstance(value, list):
            for v in value:
                yield from strings(v)
    users = {m.group(1) for s in strings(report) for m in HOME_USER.finditer(s)}

    def clean(text):
        text = SECRET.sub('<REDACTED_SECRET>', text)
        text = KEY_LITERAL.sub('<DEMO_KEY>', text)
        text = EMAIL.sub('<EMAIL>', text)
        text = PATH.sub('<PATH>', text)
        for user in sorted(users, key=len, reverse=True):
            text = re.sub(r'(?<!\w)' + re.escape(user) + r'(?!\w)', '<USER>', text, flags=re.I)
        return text

    def walk(value):
        if isinstance(value, dict):
            return {clean(str(k)): '<REDACTED>' if str(k).lower() in PRIVATE_FIELDS
                    else walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, str):
            return clean(value)
        return value
    return walk(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error('Choose a separate output file; original evidence must be preserved.')
    result = sanitize_report(json.loads(args.source.read_text(encoding='utf-8')))
    with args.destination.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)


if __name__ == '__main__':
    main()
