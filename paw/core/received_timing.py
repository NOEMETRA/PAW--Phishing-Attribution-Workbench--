"""Descriptive comparisons of unverified Received claims, never delivery proof."""
import datetime


def _aware_timestamp(value):
    try:
        parsed = datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
        return parsed if parsed.utcoffset() is not None else None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def adjacent_timestamp_observations(hops):
    dates = [_aware_timestamp(hop.get('date')) for hop in hops]
    pairs = []
    for index in range(1,len(hops)):
        earlier,later = dates[index-1:index+1]
        delta = (later-earlier).total_seconds() if earlier is not None and later is not None else None
        pairs.append({'earlier_position':index-1,'later_position':index,
            'earlier_header_index':hops[index-1].get('header_index'),
            'later_header_index':hops[index].get('header_index'),
            'status':'completed' if delta is not None else 'not_evaluated',
            'delta_seconds':delta,'result':None if delta is None else 'backward' if delta<0 else 'forward' if delta>0 else 'equal',
            'source':'Adjacent Received timestamp claims','verified':False,
            'reason':'Claimed timestamps only; clocks and delivery not verified' if delta is not None else 'Adjacent aware timestamp unavailable'})
    return pairs


def observe_received_timing(hops, reference_time=None):
    reference = datetime.datetime.now(datetime.timezone.utc) if reference_time is None else _aware_timestamp(reference_time)
    if reference is None:
        raise ValueError('Timing reference must have an explicit timezone')
    reference = reference.astimezone(datetime.timezone.utc)
    pairs = adjacent_timestamp_observations(hops)
    completed = sum(pair['status']=='completed' for pair in pairs)
    timestamps = []
    addresses = {}
    for position,hop in enumerate(hops):
        date = _aware_timestamp(hop.get('date'))
        delta = (date-reference).total_seconds() if date is not None else None
        timestamps.append({'position':position,'header_index':hop.get('header_index'),
            'value':hop.get('date'),'status':'parsed' if date is not None else 'unavailable',
            'delta_to_reference_seconds':delta,'after_reference':None if delta is None else delta>0,
            'source':'Received timestamp claim','verified':False})
        if hop.get('ip'):
            addresses.setdefault(hop['ip'],[]).append((position,hop.get('header_index')))
    repeated = [{'ip':ip,'positions':[position for position,_ in entries],
                 'header_indices':[header_index for _,header_index in entries],
                 'source':'Repeated selected Received IP claims','verified':False}
                for ip,entries in addresses.items() if len(entries)>1]
    return {'timing_schema_version':1,
        'status':'unavailable' if not hops else 'partial' if any(item['status']=='unavailable' for item in timestamps) else 'observed_unverified',
        'comparison_status':'not_evaluated' if not completed else 'completed' if completed==len(pairs) else 'partial',
        'source':'Received timestamp and address claims','verified':False,
        'reference_time':reference.isoformat(),'reference_source':'Analysis host clock; not independently verified',
        'adjacent_pairs':pairs,'timestamps':timestamps,'repeated_ip_claims':repeated,
        'interpretation_status':'not_evaluated',
        'limitation':'Timestamp order, intervals and repeated address claims do not establish malicious relays or timestamp manipulation'}
