"""Literal Markdown views of evidence; original values remain in JSON artifacts."""
import json
import re


def markdown_literal(value, *, table=False):
    """Render one JSON value as code, including escaped controls and Unicode.

    JSON quoting keeps whitespace and backticks away from code-span boundaries.
    GFM splits tables before parsing inline code, so pipes need table escaping.
    """
    text = json.dumps(value, ensure_ascii=True)
    fence = '`' * (max(map(len, re.findall(r'`+', text)), default=0) + 1)
    if table:
        text = text.replace('|', '\\|')
    return fence + text + fence


def markdown_json(value):
    """Publish parseable JSON as a fenced data block, never Markdown source.

    JSON escapes string newlines, so source strings cannot introduce a closing
    fence on a line of their own. No source text is interpolated outside JSON.
    """
    return '```json\n' + json.dumps(value, indent=2, ensure_ascii=True) + '\n```\n'


def publication_json(value):
    """Bound the literal view; source artifacts/caller values are not modified."""
    try:
        encoded = json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError, OverflowError):
        return markdown_json({'status':'not_evaluated', 'reason':'Source is not finite JSON data'})
    limit = 256 * 1024
    if len(encoded) > limit:
        return markdown_json({'status':'not_evaluated', 'reason':'Literal publication limit exceeded; consult source artifact',
                              'encoded_characters':len(encoded), 'limit':limit})
    return '```json\n' + encoded + '\n```\n'


def rekor_report(anchor, proof, errors=None):
    return ('## Rekor (stored provider fields)\n'
            'Provider field presence is not inclusion verification or authenticity.\n\n'
            + publication_json({'verification':{'status':'not_evaluated', 'result':None,
                'reason':'No validated Rekor inclusion verifier'}, 'anchor':anchor, 'proof':proof,
                'artifact_errors':errors or {}}))
