"""Bounded CID candidate equality; never resource resolution or rendering."""
import hashlib
from .html_contexts import HTMLTextContextParser
import re
from urllib.parse import unquote_to_bytes

SIMPLE_ATTRIBUTES = {'src', 'href', 'action', 'formaction', 'poster', 'data',
                     'background', 'cite', 'longdesc', 'usemap'}
LIMITATION = ('Candidate equality in captured MIME message scope, not renderer selection, '
              'RFC addr-spec validation, authenticity or execution. HTML attribute views '
              'are parser-derived; text hashes identify parser input. CSS/srcset marker '
              'observations are not parsed references. Inner/attached HTML, Content-Location '
              'and mid URLs are outside this scope; existing URLs and scores are unchanged.')


def _identifier(value):
    if not value or not value.isascii() or re.search(r'[\x00-\x20\x7f<>]', value):
        return None
    return value


def inventory_mime_cids(mime_result, body_inventory, header_inventory,
                        max_observations=2048, max_links=4096,
                        max_value_bytes=4096, max_total_value_bytes=262144):
    for limit in (max_observations, max_links, max_value_bytes, max_total_value_bytes):
        if type(limit) is not int or limit <= 0:
            raise ValueError('CID inventory limits must be positive integers')
    if body_inventory['source'] != header_inventory['source']:
        raise ValueError('CID source inventories do not match')
    used_bytes = 0
    issues = set()

    def retain(value):
        nonlocal used_bytes
        if value is None:
            return None
        size = len(value.encode('utf-8'))
        if size > max_value_bytes or used_bytes+size > max_total_value_bytes:
            issues.add('value_capture_limit')
            return None
        used_bytes += size
        return value

    ids, lookup = [], {}
    complete = not header_inventory['omitted_part_count']
    contexts = {}
    for part in header_inventory['parts']:
        contexts[part['part_id']] = part['message_root_part_id']
        fields = part['headers']
        if fields['omitted_field_count']:
            complete = False
        for field in fields['fields']:
            if field['normalized_name'] is None:
                complete = False
            if field['normalized_name'] != 'content-id':
                continue
            value = field['parsed_value'] if field['parsed_status'] == 'completed' else None
            text = value.strip() if value is not None else ''
            identifier = _identifier(text[1:-1]) if text.startswith('<') and text.endswith('>') else None
            captured = retain(identifier)
            record = {'content_id_index':len(ids), 'part_id':part['part_id'],
                'message_root_part_id':part['message_root_part_id'], 'header_index':field['header_index'],
                'artifact':'mime_header_inventory.json', 'representation':'parsed_content_id_field',
                'parsed_status':field['parsed_status'], 'identifier':captured,
                'interpretation_status':'candidate' if captured is not None else 'not_interpreted',
                'interpretation_reason':('parsed_value_unavailable' if value is None else
                    'unsupported_identifier_form' if identifier is None else
                    'value_capture_limit' if captured is None else None)}
            ids.append(record)
            if captured is not None:
                lookup.setdefault((part['message_root_part_id'],captured), []).append(record['content_id_index'])
            else:
                complete = False
    if not complete:
        issues.add('content_id_inventory_incomplete')

    parts = {part['part_id']:part for part in body_inventory['parts']}
    sources, observations, links = [], [], []
    total = total_links = direct = complex_count = 0

    def observe(source_index, element_index, tag, attribute_index, name, value):
        nonlocal total, total_links, direct, complex_count
        simple = name in SIMPLE_ATTRIBUTES and value.lower().startswith('cid:')
        complex_context = name in {'style','srcset'} and 'cid:' in value.lower()
        if not simple and not complex_context:
            return
        ordinal = total
        total += 1
        if simple: direct += 1
        else: complex_count += 1
        if len(observations) >= max_observations:
            issues.add('observation_limit')
            return
        captured = retain(value)
        identifier = None
        reason = 'complex_attribute_not_parsed' if complex_context else 'reference_not_interpreted'
        if captured is None: reason = 'value_capture_limit'
        if simple and captured is not None:
            suffix = captured[4:]
            if not re.search(r'%(?![0-9a-fA-F]{2})', suffix):
                try: identifier = _identifier(unquote_to_bytes(suffix).decode('ascii'))
                except UnicodeDecodeError: pass
            reason = None if identifier is not None else 'unsupported_or_malformed_identifier'
        root = sources[source_index]['message_root_part_id']
        if root is None: reason = 'message_scope_unavailable'
        matches = lookup.get((root,identifier), ()) if identifier is not None and root is not None else ()
        status = ('not_interpreted' if identifier is None or root is None else
                  'candidate_match' if len(matches)==1 else
                  'ambiguous_candidates' if matches else 'unmatched_in_captured_fields')
        record = {'observation_index':ordinal, 'source_index':source_index,
                  'element_index':element_index, 'tag':tag, 'attribute_index':attribute_index,
                  'attribute':name, 'parsed_attribute_value':captured,
                  'value_status':'captured' if captured is not None else 'limited',
                  'parsed_value_utf8_bytes':len(value.encode('utf-8')),
                  'interpretation_status':status, 'reason':reason,
                  'candidate_count':len(matches)}
        observations.append(record)
        for index in matches:
            total_links += 1
            if len(links) < max_links:
                links.append({'observation_index':ordinal,'content_id_index':index})

    class Parser(HTMLTextContextParser):
        def __init__(self, source_index):
            super().__init__(convert_charrefs=True)
            self.source_index, self.element_index = source_index, 0
        def handle_starttag(self, tag, attrs):
            element = self.element_index
            self.element_index += 1
            for index,(name,value) in enumerate(attrs):
                if value: observe(self.source_index, element, tag, index, name, value)

    for body in mime_result['body_parts']:
        if body['metadata']['content_type'] != 'text/html':
            continue
        part = parts[body['part_id']]
        value = body['text']
        # Bind the parser input to the persisted charset-derived view where available.
        if part['text_status']=='captured' and hashlib.sha256(value.encode('utf-8')).hexdigest()!=part['text_sha256']:
            raise ValueError('CID HTML input does not match persisted text')
        root = contexts.get(body['part_id'])
        if root is None or part['text_status']!='captured':
            issues.add('html_source_unavailable')
        source = {'source_index':len(sources),'part_id':body['part_id'],'message_root_part_id':root,
            'artifact':'mime_body_evidence.json','representation':'html_parser_attribute_values',
            'derived_from':{'representation':'per_part_charset_decoded_text',
                            **{key:part[key] for key in ('text_path','text_sha256','text_status')}}}
        sources.append(source)
        parser = Parser(source['source_index']);parser.feed(value);parser.close()
    if total_links > len(links): issues.add('link_limit')
    if complex_count: issues.add('complex_attributes_not_parsed')
    uninterpreted = sum(item['interpretation_status']=='not_interpreted' for item in observations)
    if uninterpreted: issues.add('observations_not_interpreted')
    return {'schema_version':1,'scope':'supported_outer_html_attributes_to_captured_same_message_content_id_fields',
        'status':'partial' if issues else 'completed','verified':False,'source':body_inventory['source'],
        'matching_method':'one_pass_ascii_percent_decoding_then_case_sensitive_identifier_equality',
        'content_id_catalog':ids,'content_id_count':len(ids),'content_id_inventory_complete':complete,
        'html_sources':sources,'observations':observations,'links':links,
        'total_observation_count':total,'inventoried_observation_count':len(observations),
        'omitted_observation_count':total-len(observations),'direct_reference_count':direct,
        'complex_attribute_count':complex_count,'total_link_count':total_links,
        'not_interpreted_observation_count':uninterpreted,
        'inventoried_link_count':len(links),'omitted_link_count':total_links-len(links),
        'link_count_scope':'retained_observations_and_interpreted_captured_content_id_fields',
        'captured_value_utf8_bytes':used_bytes,'issues':sorted(issues),
        'limits':{'max_observations':max_observations,'max_links':max_links,
                  'max_value_utf8_bytes':max_value_bytes,'max_total_value_utf8_bytes':max_total_value_bytes},
        'limitation':LIMITATION}


def cid_coverage(inventory):
    keys = ('status','scope','verified','content_id_count','content_id_inventory_complete',
            'total_observation_count','inventoried_observation_count','omitted_observation_count',
            'total_link_count','inventoried_link_count','omitted_link_count')
    return {**{key:inventory[key] for key in keys},'artifact':'mime_cid_inventory.json',
            'limitation':inventory['limitation']}
