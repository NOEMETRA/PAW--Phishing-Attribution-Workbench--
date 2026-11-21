"""Local text scores for an existing PAW case, for analyst review."""
from contextlib import redirect_stdout
from hashlib import sha256
import io
import json
import os
import re

from blake3 import blake3

from .batch import read_source_bytes
from .evidence import file_inventory
from .html_contexts import HTMLTextContextParser
from .job_registry import require_stopped_case
from .network_policy import offline_policy
from .source_inspection import admit_path
from .verify import verify_case


MODEL_ID = 'Horizon-Labs/phishing-scam-detector-base'
MODEL_REVISION = 'c294bf142ff53db24dc9ef07f20149ffeddeae6d'
MODEL_SHA256 = '93b2e8e547770b940bba9776dc9139fcacc02c98589bf32eb181025cc76509e0'
TOKENIZER_SHA256 = 'e7322a5d841fcfe921a2457104f85e5bfd2fbb03cdbbe495ce6c04365b9f670a'
MODEL_BYTES = 641_128_988
TOKENIZER_BYTES = 34_363_286
LABELS = ('legitimate', 'spam', 'fraud')
TOKEN_LIMIT = 384
TEXT_BYTE_LIMIT = 8 * 1024**2


class _ModelTextParser(HTMLTextContextParser):
    _BOUNDARIES = frozenset({
        'address', 'article', 'aside', 'blockquote', 'br', 'dd', 'div', 'dl', 'dt',
        'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4',
        'h5', 'h6', 'header', 'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section',
        'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'ul',
    })

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fragments = []

    def handle_starttag(self, tag, attrs):
        if tag in self._BOUNDARIES:
            self.fragments.append(' ')

    def handle_endtag(self, tag):
        if tag in self._BOUNDARIES:
            self.fragments.append(' ')

    def handle_data(self, data):
        if self.cdata_elem not in ('script', 'style'):
            self.fragments.append(self.text_data(data))


def _case_text(case):
    files = file_inventory(case)
    scope_name = 'evidence/inventory_scope.json'
    if not {scope_name, 'manifest.json', 'input.eml'} <= files.keys():
        raise ValueError('Text triage requires a complete case evidence inventory')
    if len(files) > 10_000 or sum(path.stat().st_size for path in files.values()) > 512 * 1024**2:
        raise ValueError('Case evidence inventory budget exceeded')
    require_stopped_case(case)
    index_path = case/'evidence/merkle_index.json'
    root_path = case/'evidence/merkle_root.bin'
    index_bytes = read_source_bytes(index_path, 8 * 1024**2)
    root_bytes = read_source_bytes(root_path, 128)
    index = json.loads(index_bytes)
    with redirect_stdout(io.StringIO()):
        valid = verify_case(case)
    if not valid:
        raise ValueError('Case evidence seal failed verification')
    if (read_source_bytes(index_path, 8 * 1024**2) != index_bytes
            or read_source_bytes(root_path, 128) != root_bytes):
        raise ValueError('Case evidence seal changed during verification')

    def sealed(relative, limit):
        if relative not in index or relative not in files:
            raise ValueError(f'Case evidence missing from inventory: {relative}')
        raw = read_source_bytes(files[relative], limit)
        if blake3(raw).hexdigest() != index[relative]:
            raise ValueError(f'Case evidence changed during reading: {relative}')
        return raw

    scope = json.loads(sealed(scope_name, 4096))
    execution = json.loads(sealed('execution.json', 1024**2))
    if scope.get('policy') != 'all_case_files_v1' or execution.get('status') != 'completed':
        raise ValueError('Text triage requires a completed, sealed PAW case')
    headers_name = 'headers.json'
    subject = json.loads(sealed(headers_name, 32 * 1024**2)).get('subject') or ''
    if not isinstance(subject, str):
        raise ValueError('Case subject must be text')
    body_name = 'mime_body_evidence.json'
    body = json.loads(sealed(body_name, 8 * 1024**2))
    parts, seen = [], set()
    evidence = []
    remaining = TEXT_BYTE_LIMIT
    for item in body['parts']:
        media_type, filename = item.get('declared_mime'), item.get('text_path')
        if media_type not in ('text/plain', 'text/html') or not filename:
            continue
        part_id = item['part_id']
        if (not re.fullmatch(r'0(?:\.[0-9]+)*', part_id)
                or filename != f"mime_body/part-{part_id.replace('.', '-')}.txt"):
            raise ValueError('Invalid case MIME text reference')
        if remaining <= 0:
            raise ValueError('MIME text budget exceeded')
        raw = sealed(filename, remaining)
        remaining -= len(raw)
        digest = sha256(raw).hexdigest()
        if digest != item['text_sha256']:
            raise ValueError('Case MIME text hash mismatch')
        text = raw.decode('utf-8')
        if media_type == 'text/html':
            parser = _ModelTextParser()
            parser.feed(text)
            parser.close()
            text = ''.join(parser.fragments)
        normalized = ' '.join(text.split())
        if normalized and normalized not in seen:
            seen.add(normalized)
            parts.append(normalized)
            evidence.append({'part_id': part_id, 'path': filename, 'sha256': digest,
                             'source_status': item.get('status')})
    text = '\n'.join([subject, *parts]).strip()
    return text, {
        'case_directory': case.name,
        'merkle_root_blake3': root_bytes.decode('ascii').strip(),
        'original_blake3': index['input.eml'],
        'subject_artifact': headers_name,
        'mime_body_artifact': body_name,
        'mime_body_status': body.get('status'),
        'text_parts_before_token_limit': evidence,
        'normalized_text_sha256': sha256(text.encode('utf-8')).hexdigest(),
    }


def _model_bytes(directory, name, size, digest):
    data = read_source_bytes(directory/name, size)
    if len(data) != size or sha256(data).hexdigest() != digest:
        raise ValueError(f'File does not match the approved Horizon Labs revision: {name}')
    return data


def _infer(text, directory):
    # ONNX Runtime can initialize its native uploader during import.
    os.environ['ORT_DISABLE_TELEMETRY'] = '1'
    try:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
    except ImportError as exc:
        raise RuntimeError('Install PAW with the [text-triage] extra to run local inference') from exc

    ort.disable_telemetry_events()
    tokenizer = Tokenizer.from_buffer(_model_bytes(directory, 'tokenizer.json', TOKENIZER_BYTES,
                                                  TOKENIZER_SHA256))
    tokenizer.no_padding()
    tokenizer.enable_truncation(max_length=TOKEN_LIMIT)
    encoded = tokenizer.encode(text)
    options = ort.SessionOptions()
    options.intra_op_num_threads = 4
    session = ort.InferenceSession(
        _model_bytes(directory, 'model_quantized.onnx', MODEL_BYTES, MODEL_SHA256),
        options, providers=['CPUExecutionProvider'],
    )
    inputs = {'input_ids': encoded.ids, 'attention_mask': encoded.attention_mask}
    logits, = session.run(['logits'], {name: np.array([value], dtype=np.int64)
                                       for name, value in inputs.items()})
    if logits.shape != (1, len(LABELS)) or not np.isfinite(logits).all():
        raise ValueError('Local text model returned invalid scores')
    values = np.exp(logits[0] - logits[0].max())
    scores = dict(zip(LABELS, map(float, values / values.sum())))
    return scores, len(encoded.ids), bool(encoded.overflowing), ort.__version__


def assess_case(case_directory, model_directory):
    """Return a descriptive score record without writing to the source case."""
    with offline_policy():
        case = admit_path(case_directory).resolve(strict=True)
        directory = admit_path(model_directory).resolve(strict=True)
        if not case.is_dir() or not directory.is_dir():
            raise ValueError('Case and model paths must be local directories')
        text, evidence = _case_text(case)
        result = {
            'schema_version': 1, 'status': 'not_evaluated',
            'scope': 'multilingual text scores for analyst review',
            'calibrated': False, 'evidence': evidence, 'scores': None,
            'model': {'id': MODEL_ID, 'revision': MODEL_REVISION, 'sha256': MODEL_SHA256,
                      'tokenizer_sha256': TOKENIZER_SHA256, 'max_tokens': TOKEN_LIMIT},
        }
        if not text:
            return dict(result, reason='No subject or captured MIME text available')
        scores, tokens, truncated, runtime = _infer(text, directory)
        return dict(result, status='completed', scores=scores, tokens=tokens, truncated=truncated,
                    onnxruntime_version=runtime)
