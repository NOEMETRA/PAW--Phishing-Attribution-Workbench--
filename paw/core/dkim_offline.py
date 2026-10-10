"""Independent DKIM verification using only analyst-supplied local DNS records."""
from email import policy
from email.parser import BytesParser
import hashlib


def verify_dkim_offline(message_bytes, dns_records=None):
    signatures = BytesParser(policy=policy.default).parsebytes(message_bytes).get_all('DKIM-Signature') or []
    if not signatures:
        return {'status': 'not_evaluated', 'result': None, 'reason': 'No DKIM signature present'}
    if not dns_records:
        return {'status': 'not_evaluated', 'result': None, 'reason': 'No local DKIM public key evidence'}
    import dkim
    records = {str(name).lower().rstrip('.'): value.encode('ascii') if isinstance(value, str) else value
               for name, value in dns_records.items()}
    used, results = set(), []
    class MissingKey(Exception): pass
    def local_dns(name, timeout=5):
        key = name.decode('ascii').lower().rstrip('.')
        if key not in records: raise MissingKey('Missing local public key: ' + key)
        used.add(key)
        return records[key]
    for index in range(len(signatures)):
        key_available = False
        try:
            verifier = dkim.DKIM(message_bytes)
            sig, _, _ = verifier.verify_headerprep(index)
            key = (sig[b's'] + b'._domainkey.' + sig[b'd']).decode('ascii').lower().rstrip('.')
            if key not in records: raise MissingKey('Missing local public key: ' + key)
            # dkimpy collapses malformed-key lookup errors to False inside
            # verify_sig. Validate the supplied record first to retain uncertainty.
            dkim.evaluate_pk(key.encode('ascii'), local_dns(key.encode('ascii')))
            key_available = True
            passed = verifier.verify(idx=index, dnsfunc=local_dns)
            results.append({'index': index, 'status': 'completed', 'result': 'pass' if passed else 'fail'})
        except MissingKey as exc:
            results.append({'index': index, 'status': 'not_evaluated', 'result': None, 'reason': str(exc)})
        except dkim.ValidationError:
            results.append({'index': index, 'status': 'completed' if key_available else 'error',
                            'result': 'fail' if key_available else None,
                            'reason': 'DKIM signature validation failed' if key_available else 'Invalid DKIM signature structure'})
        except Exception as exc:
            results.append({'index': index, 'status': 'error', 'result': None, 'reason': type(exc).__name__})
    result = 'pass' if any(item['result'] == 'pass' for item in results) else 'fail' if all(item['result'] == 'fail' for item in results) else None
    return {'status': 'completed' if result is not None else 'not_evaluated', 'result': result,
            'source': 'independent_DKIM_with_local_keys', 'key_provenance_status': 'unverified',
            'verification_scope': 'signature_with_supplied_keys', 'signatures': results, 'key_names': sorted(used),
            'message_sha256': hashlib.sha256(message_bytes).hexdigest(),
            'key_record_sha256': {name: hashlib.sha256(records[name]).hexdigest() for name in sorted(used)},
            'limitation': 'Local key provenance must be established separately; no external DNS was queried'}
