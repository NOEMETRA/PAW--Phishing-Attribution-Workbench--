"""Actual offline CSS token boundaries and publication, without resource access."""
import base64
from email import policy
from email.message import EmailMessage
from html import escape

from integration_html_url_lists_real import main


def markup(css,attribute=False):
    return '<div style="'+escape(css,quote=True)+'"></div>' if attribute else '<style>'+css+'</style>'


def fixtures():
    url = 'https://actual.invalid/a'
    trivia = ' /* https://comment.invalid/a ) */\t/**/'
    opaque = 'url("'+url+'"/* ) https://comment.invalid/a */ junk("x)"))'
    incomplete = 'url("'+url+'"/* https://comment.invalid/a )'
    encoded = base64.b64encode(b'https://encoded.invalid/a%2Fb').decode()
    budget_urls = [f'https://slot.invalid/a{index}' for index in range(50)]
    budget_trivia = [f'/* https://comment.invalid/a{index} ) */' for index in range(50)]
    budget_sources = [value for pair in zip(budget_urls,budget_trivia) for value in pair]
    budget_css = ''.join('a:url("'+value+'"'+comment+');' for value,comment in zip(budget_urls,budget_trivia))
    rows = {
        'quoted-comments.eml': ([markup('url("'+url+'"/**/)',True),markup('url("'+url+'"/* ) \' ( */)')],
                                [url],[url],2),
        'opaque-trivia.eml': ([markup('url("'+url+'"'+trivia+')')],[url],[url,trivia],2),
        'nonnetwork.eml': ([markup('url("data:text/plain,https://inner.invalid/a"'+trivia+')',True)],[],[trivia],1),
        'token-names.eml': ([markup('#url(https://hash.invalid/a) @url(https://keyword.invalid/a)')],
                            ['https://hash.invalid/a)','https://keyword.invalid/a)'],
                            ['https://hash.invalid/a)','https://keyword.invalid/a)'],2),
        'nested-function.eml': ([markup('#url(url('+url+')) @url(url('+url+'))',True)],[url],[url],1),
        'invalid-escape.eml': ([markup('prefix\\\r\nurl('+url+')',True)],[url],[url],1),
        'unsupported.eml': ([markup(opaque)],[],[opaque],1),
        'incomplete.eml': ([markup(incomplete)],[],[incomplete],1),
        'recovered.eml': ([markup('url("'+encoded+'"/**/) url("hxxps://actual[.]invalid/a"/**/)')],
                          ['https://encoded.invalid/a%2Fb',url],[encoded,'hxxps://actual[.]invalid/a'],2),
        'multipart.eml': ([markup('unfinished'),markup('url("'+url+'"'+trivia+')',True)],
                          [url],[url,trivia],2),
        'budget.eml': ([markup(budget_css)]*50,budget_urls,budget_sources,5000)}
    samples = {}
    for name,(parts,targets,sources,count) in rows.items():
        message = EmailMessage(policy=policy.SMTP)
        message['From']='fixture@example.invalid';message['Subject']='CSS token boundary regression'
        message.set_content(parts[0],subtype='html')
        for part in parts[1:]: message.add_alternative(part,subtype='html')
        samples[name]=(message.as_bytes(),targets,sources,count)
    return samples


if __name__=='__main__':
    main(samples=fixtures(),http_names=('opaque-trivia.eml','token-names.eml','unsupported.eml','budget.eml'),
         summary='Quoted URL comment separators, opaque separator evidence without inner targets, '
         'hash/at-keyword names versus actual nested functions, invalid identifier escapes, '
         'whole unsupported/EOF quoted functions, recovered origins, independent MIME views, source v6, '
         '5000/4096/904 source accounting, raw/body hashes, coverage, stopped owners, seals and CLI/API/ZIP '
         'parity. Not full CSS grammar, browser/resource use or classifier accuracy.')
