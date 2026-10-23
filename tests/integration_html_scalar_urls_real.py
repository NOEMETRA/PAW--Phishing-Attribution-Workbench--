"""Actual full scalar HTML URL cases and loopback exports; never navigate fields."""
import base64
from email import policy
from email.message import EmailMessage
from html import escape
from urllib.parse import quote

from integration_html_url_lists_real import main


def field(tag,name,value):
    return '<'+tag+' '+name+'="'+escape(value,quote=True)+'">go</'+tag+'>'


def fixtures():
    fields = [('a','href'),('img','src'),('form','action'),('button','formaction'),('video','poster'),('object','data')]
    nonnetwork = ['data:text/plain,https://embedded.invalid/a','/relative?next=https://embedded.invalid/a',
                  '//one.invalid/?next=https://embedded.invalid/a',"javascript:send('https://embedded.invalid/a')"]
    resources = [f"HTTPS://slot{index}.invalid/O'Reilly,a%29b?x=1&y=2#e'f" for index in range(6)]
    invalid = ['https://one.invalid/a tail','https://one.invalid/a"tail',
               'https://one.invalid/a<tail',' https://one.invalid/a ']
    target = 'https://one.invalid/a%2Fb?next=https://nested.invalid/c'
    recovered = [target.replace('https://one.invalid','hxxps://one[.]invalid'),
                 quote(target,safe=''),base64.b64encode(target.encode()).decode()]
    multiple = 'https://one.invalid/a https://two.invalid/b'
    valid = "https://valid.invalid/O'Reilly"
    metadata = [f'https://metadata{index}.invalid/a' for index in range(3)]
    budget = [f"https://slot.invalid/O'Reilly{index}" for index in range(100)]
    repeated = field('a','href',valid)+field('img','src',nonnetwork[0])
    rows = {
        'nonnetwork.eml': ([''.join(field(tag,name,value) for tag,name in fields for value in nonnetwork)],[],nonnetwork,4),
        'resources.eml': ([''.join(field(tag,name,value) for (tag,name),value in zip(fields,resources))],resources,resources,6),
        'invalid.eml': ([''.join(field('a','href',value) for value in invalid)],[],invalid,4),
        'recovered.eml': ([''.join(field('a','href',value) for value in recovered)],[target],recovered,3),
        'multiple.eml': ([field('a','href',multiple)+field('a','href',valid)],[valid],[multiple,valid],2),
        'metadata.eml': ([''.join(field('div',name,'please inspect '+value)
                         for name,value in zip(('data','data-next','title'),metadata))],metadata,metadata,3),
        'multipart.eml': ([repeated]*3,[valid],[valid,nonnetwork[0]],6),
        'budget.eml': ([''.join(field('a','href',value) for value in budget)]*50,budget,budget,5000)}
    samples = {}
    for name,(parts,targets,sources,count) in rows.items():
        message = EmailMessage(policy=policy.SMTP)
        message['From'] = 'fixture@example.invalid'; message['Subject'] = 'Scalar HTML URL fixture'
        message.set_content(parts[0],subtype='html')
        for part in parts[1:]: message.add_alternative(part,subtype='html')
        samples[name] = (message.as_bytes(),targets,sources,count)
    return samples


if __name__=='__main__':
    main(samples=fixtures(),http_names=('nonnetwork.eml','invalid.eml','budget.eml'),
         summary='Whole scalar HTML URL fields versus embedded HTTP substrings and truncated prefixes, '
         'legal punctuation and entity identity, original invalid/nonnetwork/recovered values, unchanged '
         'metadata extraction, repeated MIME views, source v6, exact 5000/4096/904 accounting, original/body bytes, '
         'coverage, stopped workers, seals and CLI/API/ZIP parity. No browser URL normalization, '
         'relative resolution, navigation, script execution or accuracy claim.')
