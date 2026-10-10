"""Unverified RDAP name binding and unambiguous registration-event selection."""
from .authentication import normalize_domain


def observe_rdap_registration(domain, data):
    record = {'registration_schema_version':1,'status':'unavailable','verified':False,
              'source':'supplied_rdap_response','scope':'exact_requested_domain_and_single_registration_event',
              'requested_domain':normalize_domain(domain) if isinstance(domain,str) else None,'object_class':None,
              'returned_ldh_name':None,'returned_domain':None,'domain_match':None,
              'registration_events':[],'created':None,
              'reason_code':'response_unavailable'}
    if not record['requested_domain']:
        record.update(status='invalid',reason_code='invalid_requested_domain')
        return record
    if data is None:
        return record
    if not isinstance(data,dict):
        record.update(status='invalid',reason_code='invalid_response_object')
        return record
    kind=data.get('objectClassName')
    record['object_class']=kind if isinstance(kind,str) else None
    name=data.get('ldhName')
    record['returned_ldh_name']=name if isinstance(name,str) else None
    # ldhName is ASCII LDH, not unicodeName. Allow DNS case and one root dot,
    # without forgiving whitespace or interpreting Unicode in this field.
    if isinstance(name,str) and name.isascii() and name==name.strip():
        bare=name[:-1] if name.endswith('.') else name
        if bare and not bare.endswith('.'):
            record['returned_domain']=normalize_domain(bare)
    if kind!='domain':
        record.update(status='invalid',reason_code='not_domain_object')
        return record
    if not record['returned_domain']:
        record.update(status='invalid',reason_code='ldh_name_unavailable_or_invalid')
        return record
    match=record['returned_domain']==record['requested_domain']
    record['domain_match']=match
    if not match:
        record.update(status='invalid',reason_code='domain_mismatch')
        return record
    events=data.get('events')
    if events is None:
        record['reason_code']='registration_event_unavailable'
        return record
    if not isinstance(events,list) or any(not isinstance(event,dict) for event in events):
        record.update(status='invalid',reason_code='invalid_events')
        return record
    for index,event in enumerate(events):
        if event.get('eventAction')=='registration':
            date=event.get('eventDate')
            record['registration_events'].append({'event_index':index,
                'event_date':date if isinstance(date,str) else None,'date_type':type(date).__name__})
    candidates=record['registration_events']
    if not candidates:
        record['reason_code']='registration_event_unavailable'
    elif len(candidates)!=1:
        record.update(status='invalid',reason_code='ambiguous_registration_events')
    elif not candidates[0]['event_date']:
        record.update(status='invalid',reason_code='invalid_registration_date')
    else:
        record.update(status='observed_unverified',reason_code='registration_event_observed',
                      created=candidates[0]['event_date'])
    # Timestamp validity/future comparison belong to observe_domain_age. Name
    # equality and a selected event do not authenticate a registry or ownership.
    return record
