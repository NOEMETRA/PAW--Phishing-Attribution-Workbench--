"""Actual supplied HTML CSS CLI/API/extraction/ZIP contract, without resource access."""
import base64
from email import policy
from email.message import EmailMessage
from html import escape

from integration_html_url_lists_real import main


def fixtures():
    one,two = 'https://one.invalid/a','https://two.invalid/b'
    quoted = "https://one.invalid/a(b),c'd?x=a,b#c(d)"
    encoded = base64.b64encode(b'https://encoded.invalid/a%2Fb').decode()
    invalid = ['https://bad.invalid/%ZZ','https://bad.invalid:bad/a',r'https://escaped.invalid/a\)tail']
    malformed = ['url(https://bad.invalid/a tail)','url("https://bad.invalid/a"junk)',
                 'url(https://bad.invalid/a']
    rows = {
        'boundaries.eml': (['<div style="a:url('+one+');b:URL( '+two+' )"></div>'
                           '<style>a{a:url('+one+');b:url('+two+')}</style>'],[one,two],[one,two],2),
        'nonnetwork.eml': (['<div style="a:url(data:text/plain,https://data.invalid/a);'
            'b:url(/relative?next=https://query.invalid/a)"></div>'
            '<style>a{a:url("data:text/plain,https://quoted.invalid/a");'
            'b:url("/relative?next=https://relative.invalid/a")}</style>'],[],[],0),
        'quoted.eml': (['<style>a{a:url("'+quoted+'");b:url(\''+two+'%29b%22c\')}</style>'],
                       [quoted,two+'%29b%22c'],[quoted,two+'%29b%22c'],2),
        'entities.eml': (['<div style="a:url(&quot;'+one+'?x=1&amp;y=2&quot;)"></div>'
            '<style>a{a:url("'+two+'?x=1&amp;y=2")}</style>'],
            [one+'?x=1&y=2',two+'?x=1&amp;y=2'],[one+'?x=1&y=2',two+'?x=1&amp;y=2'],2),
        'invalid.eml': (['<div style="'+escape('a{'+''.join('x:url('+v+');' for v in invalid)+'}',quote=True)+'"></div>'],[],invalid,3),
        'malformed.eml': (['<style>'+value+'</style>' for value in malformed],[],malformed,3),
        'encoded.eml': (['<style>a{a:url(hxxps://one[.]invalid/a%2Fb);b:url('+encoded+')}</style>'],
            ['https://one.invalid/a%2Fb','https://encoded.invalid/a%2Fb'],
            ['hxxps://one[.]invalid/a%2Fb',encoded],2),
        'multipart.eml': (['<style>unfinished','<style>a{a:url('+one+')}</style>',
                           '<div style="a:url('+two+')"></div>'],[one,two],[one,two],2)}
    result = {}
    for name,(parts,targets,sources,count) in rows.items():
        message = EmailMessage(policy=policy.SMTP)
        message['From'] = 'fixture@example.invalid'; message['Subject'] = 'CSS boundary regression fixture'
        message.set_content(parts[0],subtype='html')
        for part in parts[1:]: message.add_alternative(part,subtype='html')
        result[name] = (message.as_bytes(),targets,sources,count)
    return result


if __name__=='__main__':
    main(samples=fixtures(),http_names=('boundaries.eml','nonnetwork.eml','malformed.eml'),
         summary='CSS url() arguments versus surrounding syntax, nonnetwork/relative component exclusion, '
         'quoted resource identity, attribute entities versus raw style text, original invalid/escaped/malformed '
         'and recovered candidates, independent MIME documents, source v3, original/body bytes, coverage, '
         'stopped workers, seals and CLI/API/ZIP parity. No CSS escape decoding, browser/resource selection '
         'or classifier accuracy claim.')
