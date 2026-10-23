"""Actual offline HTML text contexts and sealed publication, not rendering."""
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import hashlib

from integration_html_url_lists_real import main, read


def fixtures():
    literal = ('<style>url(https://text.invalid/a)</style>'
               '<form action="https://form.invalid/a"><input name="password"></form>'
               '<script>eval("https://script.invalid/a")</script>'
               '<img src="cid:logo@local.invalid">'
               '<img src="data:text/plain;base64,YQ==" style="display:none">')
    lexical = ['https://text.invalid/a)', 'https://form.invalid/a', 'https://script.invalid/a']
    rows = {tag+'.eml': ([f'<{tag}>{literal}</{tag}>'],lexical,lexical,3)
            for tag in ('textarea','title','xmp','iframe','noembed','noframes','plaintext')}
    rows.update({
        'selfclosing.eml': (['<textarea/>'+literal+'</textarea>'],lexical,lexical,3),
        'unclosed.eml': (['<textarea>'+literal],lexical,lexical,3),
        'malformed-eof.eml': (['<textarea>'+'</textarea x="'*50000],[],[],0),
        'entities.eml': (['<textarea>https://entity.invalid/?x=1&amp;y=2</textarea>'
                          '<xmp> https://raw.invalid/?x=1&amp;y=2 </xmp>'],
                         ['https://entity.invalid/?x=1&y=2','https://raw.invalid/?x=1&amp;y=2'],
                         ['https://entity.invalid/?x=1&y=2','https://raw.invalid/?x=1&amp;y=2'],2),
        'end-token.eml': (['<textarea>literal</textarea attr="a>b"><a href="https://after.invalid/">after</a>'],
                          ['https://after.invalid/'],['https://after.invalid/'],1),
        'multipart.eml': (['<plaintext>https://first.invalid/a',
                           '<form action="https://second.invalid/b"><input name="real"></form>'],
                          ['https://first.invalid/a','https://second.invalid/b'],
                          ['https://first.invalid/a','https://second.invalid/b'],2),
        'multipart-rcdata.eml': (['<textarea>https://first.invalid/a',
                           '<form action="https://second.invalid/b"><input name="real"></form>'],
                          ['https://first.invalid/a','https://second.invalid/b'],
                          ['https://first.invalid/a','https://second.invalid/b'],2)})
    budget = [f'https://slot.invalid/a{index}' for index in range(100)]
    rows['budget.eml'] = (['<textarea>'+' '.join(budget)+'</textarea>']*50,budget,budget,5000)
    samples = {}
    for name,(parts,targets,sources,count) in rows.items():
        message = EmailMessage(policy=policy.SMTP)
        message['From'] = 'fixture@example.invalid'; message['Subject'] = 'HTML text context fixture'
        message.set_content(parts[0],subtype='html')
        for part in parts[1:]: message.add_alternative(part,subtype='html')
        samples[name] = (message.as_bytes(),targets,sources,count)
    return samples


def check_context(case,sample):
    message = BytesParser(policy=policy.default).parsebytes(sample[0])
    parts = [part.get_content() for part in message.walk() if part.get_content_type()=='text/html']
    result = read(case/'deobfuscation_results.json')
    html = result['deobfuscated_artifacts']['html']
    documents = html['documents'] if len(parts)>1 else [html]
    assert [row['original_html'] for row in documents] == parts
    assert all(row['original_html']==row['final_html'] for row in documents)
    bodies = [row for row in read(case/'mime_body_evidence.json')['parts'] if row['declared_mime']=='text/html']
    assert len(documents)==len(bodies)
    for index,(document,body) in enumerate(zip(documents,bodies)):
        source = document['source']
        assert source == {'artifact':'mime_body_evidence.json','part_id':body['part_id'],
                         'representation':'per_part_charset_decoded_text',
                         **{key:body[key] for key in ('text_status','text_path','text_sha256')}}
        assert hashlib.sha256((case/source['text_path']).read_bytes()).hexdigest()==source['text_sha256']
        if len(parts)>1: assert document['document_index']==index
    if len(parts)==2:
        assert html['html_schema_version']==3
        assert [len(row['form_analysis']['forms']) for row in documents]==[0,1]
        assert documents[1]['form_analysis']['forms'][0]['inputs'][0]['name']=='real'
    assert html['risk_detection']=='not_evaluated' and not html['calibrated']
    if len(parts)==1:
        assert html['form_analysis']['forms']==[]
        assert html['javascript_analysis']['inline_scripts']==[]
        assert html['encoded_attribute_candidates']['candidates']==[]
        assert html['hidden_elements']==[]
        assert len(html['iframe_analysis']['iframes'])==int(parts[0].startswith('<iframe>'))
    assert read(case/'headers.json')['deobfuscation_analysis']==result
    cid = read(case/'mime_cid_inventory.json')
    assert cid['total_observation_count']==0 and cid['total_link_count']==0
    assert 'HTML text-context boundaries are lexical' in read(case/'analysis_coverage.json')['stages']['url_interpretation']['limitation']


if __name__=='__main__':
    main(samples=fixtures(), http_names=('textarea.eml','entities.eml','multipart.eml','multipart-rcdata.eml','malformed-eof.eml','budget.eml'),
         case_check=check_context,
         summary='RCDATA once-only entities, RAWTEXT/plaintext literal content, no fabricated form/script/'
         'hidden/encoded/CID nodes in single documents, selfclosing/EOF boundaries and a 700KB incomplete end token, independent MIME '
         'URL and HTML observation views with per-part hashes, source v6, exact 5000/4096/904 links, unchanged raw/body bytes, stopped owners, '
         'coverage, seals and CLI/API/ZIP parity. Not HTML5 tree construction, browser behavior or accuracy labels.')
