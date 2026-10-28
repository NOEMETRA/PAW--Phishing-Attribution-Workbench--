"""Explicit classic-JavaScript bytes to a separate browser HTML candidate.

The host only encodes data. This is not Node.js, script execution or a browser
parser. The resulting document is an operator-selectable derived representation,
not a replacement for the source and not execution authority.
"""
import base64

MAX_SOURCE = 256*1024
MAX_WRAPPER = 512*1024
TRANSFORM = 'javascript-to-browser-html'


def browser_bytes(raw):
    if type(raw) is not bytes or len(raw) > MAX_SOURCE: raise ValueError('javascript_source_bytes')
    try: raw.decode('utf-8', 'strict')
    except UnicodeError as error: raise ValueError('javascript_strict_utf8_required') from error
    # Only the Base64 alphabet enters the quoted attribute. Closing script tags,
    # quotes and arbitrary HTML in the original never become document markup.
    wrapper = (b'<!doctype html><meta charset="utf-8"><title>PAW explicit JavaScript view</title>\n'
               b'<script src="data:text/javascript;charset=utf-8;base64,'+base64.b64encode(raw)+b'"></script>\n')
    if len(wrapper) > MAX_WRAPPER: raise ValueError('javascript_wrapper_bytes')
    return wrapper


def observe_javascript(graph, parent):
    node = graph.nodes[parent]
    result = {'schema': 'paw-forensic-javascript-browser-v1', 'source_representation': parent,
              'source_sha256': node['sha256'], 'status': 'partial', 'issues': [], 'browser_representation': None,
              'scope': 'classic script embedded as Base64 in a new HTML document; no host execution',
              'environment': 'new document/origin and relative-URL semantics; no Node.js or module environment',
              'maximum_source_bytes': MAX_SOURCE, 'maximum_wrapper_bytes': MAX_WRAPPER,
              'origin_verified': False, 'execution_authority': 'none'}
    if node['bytes'] > MAX_SOURCE:
        graph.omit(parent, TRANSFORM, 'javascript_source_bytes'); result['issues'].append('javascript_source_bytes'); return result
    raw = graph.spend(parent, TRANSFORM)
    if raw is None: result['issues'].append('graph_work_budget'); return result
    try: wrapper = browser_bytes(raw)
    except ValueError as error:
        graph.omit(parent, TRANSFORM, str(error)); result['issues'].append(str(error)); return result
    identifier = graph.add('browser_html_candidate', wrapper, [parent], TRANSFORM,
        {'input_charset': 'utf-8', 'errors': 'strict', 'embedding': 'base64-data-classic-script',
         'source_sha256': node['sha256'], 'environment': 'new_document_and_origin'}, complete=True,
        notes=['explicit_derived_browser_view_not_original_or_authenticated',
               'document_origin_and_relative_URL_behavior_differ_from_a_standalone_runtime'])
    if identifier is None: result['issues'].append('graph_representation_budget'); return result
    result.update(status='derived_candidate', browser_representation=identifier,
                  browser_sha256=graph.nodes[identifier]['sha256'], browser_bytes=len(wrapper))
    return result
