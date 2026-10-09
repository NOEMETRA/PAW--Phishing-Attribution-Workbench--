"""Offline observations for a deliberately narrow mailbox-domain scope."""
from email import policy
from .authentication import normalize_domain


def reply_domain_observation(value, count=1, field_defects=()):
    observation = {'status':'unavailable','domain':None,
                   'scope':'single_ungrouped_mailbox','source':'message_headers',
                   'verification':'not_evaluated','reason':'No Reply-To field'}
    if count == 0:
        return observation
    if count != 1:
        observation.update(status='unsupported',reason='Reply-To occurrence count is not one')
        return observation
    if field_defects:
        observation.update(status='partial',reason='Reply-To field has reported parsing defects')
        return observation
    if not value:
        observation.update(status='partial',reason='Empty Reply-To mailbox')
        return observation
    try:
        field = value if hasattr(value,'addresses') else policy.default.header_factory('Reply-To',str(value))
        if field.defects:
            observation.update(status='partial',reason='Reply-To field has reported parsing defects')
        elif len(field.groups) != 1 or field.groups[0].display_name is not None or len(field.addresses) != 1:
            observation.update(status='unsupported',reason='Grouped or multiple mailboxes outside supported domain scope')
        else:
            address = field.addresses[0]
            domain = normalize_domain(address.domain)
            if not address.username or not domain:
                observation.update(status='partial',reason='Complete normalized mailbox domain unavailable')
            else:
                observation.update(status='parsed',domain=domain,reason='Mailbox domain parsed; identity not verified')
    except (ValueError, TypeError, AttributeError, IndexError):
        observation.update(status='partial',reason='Structured Reply-To parsing unavailable')
    return observation
