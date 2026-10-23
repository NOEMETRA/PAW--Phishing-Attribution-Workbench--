"""Bounded links to existing outer-message URL records; no new URL interpretation."""
import hashlib
from itertools import islice
from .mime_analysis import HtmlEvidenceParser, extract_urls
from .url_evidence import extract_text_url_candidates, extract_mime_url_candidates


def inventory_url_sources(mime_result, body_inventory, message, headers,
                          header_inventory, evidence, max_links=4096, max_unmapped=256):
    """Record per-source presence, not raw byte positions or occurrence counts.

    Inputs are the same bounded MIME/selected-header views used by trace_one.
    Only exact candidate strings matching an existing record's original source
    are linked. Destinations, record order and interpretation stay unchanged.
    """
    for value in (max_links, max_unmapped):
        if type(value) is not int or value <= 0:
            raise ValueError('URL source inventory limits must be positive integers')
    raw = getattr(message, '_paw_source_bytes', None)
    if not isinstance(raw, bytes):
        raise ValueError('URL source links require a bound original message')
    source = {'path':'input.eml','sha256':hashlib.sha256(raw).hexdigest()}
    if body_inventory['source'] != source or header_inventory['source'] != source:
        raise ValueError('URL source inventories do not match the original message')
    indexes = {}
    for index, record in enumerate(evidence):
        value = record.get('source_url', record['url'])
        indexes.setdefault(value, []).append(index)
    sources, links, mapped = [], [], set()
    total = 0

    def add(source, candidates):
        nonlocal total
        identifier = len(sources)
        source['source_index'] = identifier
        sources.append(source)
        for value in dict.fromkeys(candidates):
            for index in indexes.get(value, ()):
                total += 1
                mapped.add(index)
                if len(links) < max_links:
                    links.append({'url_evidence_index':index, 'source_index':identifier})

    persisted = {part['part_id']:part for part in body_inventory['parts']}
    for body in mime_result['body_parts']:
        metadata, value = body['metadata'], body['text']
        field = persisted[body['part_id']]
        content_type = metadata['content_type']
        if content_type == 'text/html':
            visible = HtmlEvidenceParser()
            visible.feed(value); visible.close()
            candidates = extract_mime_url_candidates({'body_text':''.join(visible.text),
                'html_parts':[value], 'javascript':''})
            # Match the MIME observer too, including its supported attribute
            # sources and malformed HTTP strings, without inventing new targets.
            candidates += visible.urls + extract_urls(''.join(visible.text))
        else:
            candidates = extract_text_url_candidates(value) + extract_urls(value)
        text_source = {'representation':'per_part_charset_decoded_text',
                       'text_status':field['text_status'], 'text_path':field['text_path'],
                       'text_sha256':field['text_sha256']}
        source_view = text_source
        if content_type == 'text/html':
            # The persisted text is parser input, not a literal occurrence of
            # entity-decoded attributes or visible text joined across markup.
            source_view = {'representation':'html_parser_derived_url_candidate_views',
                           'derived_from':text_source,
                           'derivation':{'method':'paw_html_url_candidate_views_v3',
                                         'persisted':False}}
        add({'kind':'mime_body', 'part_id':body['part_id'],
             'artifact':'mime_body_evidence.json', **source_view}, candidates)

    retained_headers = {field['header_index']:field for field in header_inventory['fields']}
    selected = set()
    for index, (name, _) in enumerate(message.raw_items()):
        normalized = name.lower()
        if normalized not in {'from','subject'} or normalized in selected:
            continue
        selected.add(normalized)
        # The pipeline uses only the first selected occurrence. Other header
        # fields and embedded headers remain separate inventories, not sources.
        value = headers.get(normalized, '')
        candidates = (extract_text_url_candidates(value) + extract_urls(value)
                      if normalized == 'subject' else extract_urls(value))
        field = retained_headers.get(index)
        add({'kind':'selected_header', 'field':normalized, 'header_index':index,
             'part_id':'0', 'artifact':'headers.json',
             'representation':'selected_parsed_top_level_header',
             'header_inventory_artifact':'header_inventory.json',
             'header_inventory_status':field['parsed_status'] if field else 'not_inventoried'}, candidates)

    unmapped_count = len(evidence)-len(mapped)
    unmapped = list(islice((index for index in range(len(evidence)) if index not in mapped), max_unmapped))
    issues = []
    if total > len(links): issues.append('source_link_limit')
    if unmapped_count: issues.append('source_not_located_in_supported_views')
    if unmapped_count > max_unmapped: issues.append('unmapped_index_limit')
    return {'schema_version':1, 'status':'partial' if unmapped_count else 'limited' if issues else 'completed',
        'scope':'existing_url_records_in_supported_outer_message_views', 'verified':False,
        'source':source,
        'url_evidence_artifact':'url_evidence.json', 'url_evidence_record_count':len(evidence),
        'sources':sources, 'source_count':len(sources), 'links':links,
        'total_link_count':total, 'inventoried_link_count':len(links), 'omitted_link_count':total-len(links),
        'mapped_evidence_count':len(mapped), 'unmapped_evidence_count':unmapped_count,
        'unmapped_evidence_indexes':unmapped,
        'omitted_unmapped_index_count':unmapped_count-len(unmapped), 'issues':issues,
        'limits':{'max_links':max_links,'max_unmapped_indexes':max_unmapped},
        'limitation':'Exact candidate presence per decoded text, HTML parser-derived candidate views or first selected Subject/From view. HTML text paths/hashes identify parser input, not literal candidate occurrences; derived views are not persisted. Not occurrence counts, raw byte offsets, all headers, attachments, execution or authenticity. URL records and targets are unchanged.'}


def url_source_coverage(inventory):
    keys = ('status','scope','verified','source_count','total_link_count','inventoried_link_count',
            'omitted_link_count','mapped_evidence_count','unmapped_evidence_count')
    return {**{key:inventory[key] for key in keys}, 'artifact':'url_source_inventory.json',
            'limitation':inventory['limitation']}
