"""Explicit unavailable status until STIX schema conformance is validated."""


def make_stix(case_id, ip, domain, asn_org):
    # Previously emitted empty IPv4/domain objects and incomplete observed-data.
    # This is a capability status record, not a STIX bundle.
    return {'status':'unavailable', 'requested':True,
            'reason':'STIX export schema conformance has not been validated',
            'case_id':case_id, 'bundle_generated':False}
