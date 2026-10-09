"""Address categories, not evidence of malicious activity or peer provenance."""
import ipaddress


def classify_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return {'category':'invalid','is_global':False}
    effective = address.ipv4_mapped if address.version == 6 and address.ipv4_mapped else address
    if effective.is_unspecified:
        category = 'unspecified'
    elif effective.is_loopback:
        category = 'loopback'
    elif effective.is_link_local:
        category = 'link_local'
    elif effective.is_multicast:
        category = 'multicast'
    elif effective.version == 4 and any(effective in ipaddress.ip_network(net) for net in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        category = 'private_rfc1918'
    elif effective.version == 6 and effective in ipaddress.ip_network('fc00::/7'):
        category = 'unique_local'
    elif effective.version == 4 and effective in ipaddress.ip_network('100.64.0.0/10'):
        category = 'shared_address_space'
    elif (effective.version == 4 and any(effective in ipaddress.ip_network(net) for net in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24'))) or (effective.version == 6 and any(effective in ipaddress.ip_network(net) for net in ('2001:db8::/32','3fff::/20'))):
        category = 'documentation'
    else:
        category = 'public' if effective.is_global else 'other_special'
    return {'category':category,'family':address.version,'is_global':category=='public',
            'stdlib_is_global':effective.is_global,
            'ipv4_mapped':str(effective) if effective != address else None}
