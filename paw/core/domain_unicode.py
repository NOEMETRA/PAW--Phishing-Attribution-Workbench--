"""Bounded IDNA representation observations; no script or homograph verdicts."""


def observe_domain_unicode(normalized_domain):
    """Accept the caller's validated, unambiguous ASCII From domain or None."""
    record = {'unicode_schema_version':1, 'status':'unavailable',
              'source':'message_headers', 'verified':False,
              'normalization':'PAW normalize_domain / Python stdlib IDNA codec (IDNA 2003)',
              'normalized_domain':normalized_domain, 'unicode_domain':None,
              'decoded_non_ascii':None, 'mixed_script':None,
              'script_analysis_status':'not_evaluated',
              'homograph_analysis_status':'not_evaluated', 'contribution':0.0,
              'reason':'Unambiguous normalized From domain unavailable'}
    if not normalized_domain:
        return record
    try:
        decoded = normalized_domain.encode('ascii').decode('idna')
    except UnicodeError:
        record.update(status='partial',reason='Normalized spelling cannot be decoded with the configured IDNA codec')
        return record
    record.update(status='observed_unverified',unicode_domain=decoded,
                  decoded_non_ascii=not decoded.isascii(),
                  reason='IDNA spelling observed; scripts, confusables and ownership not evaluated')
    return record
