"""Exact operator-owned endpoint authorized for one controlled GET."""
PUBLIC_HOST = 'squishylab.fun'
PUBLIC_PATH = '/'
PUBLIC_URL = 'https://' + PUBLIC_HOST + PUBLIC_PATH
PUBLIC_TARGETS = {'apex': PUBLIC_HOST, 'www': 'www.squishylab.fun'}
FIXTURE_HOST = 'allow.fixture.invalid'
FIXTURE_PATH = '/get'


def public_scope(target):
    if type(target) is not str or target not in PUBLIC_TARGETS:
        raise ValueError('fixed_target_only')
    host = PUBLIC_TARGETS[target]
    return host, 'https://' + host + PUBLIC_PATH
