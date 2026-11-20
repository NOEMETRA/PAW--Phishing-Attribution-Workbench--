"""Render three synthetic engine decisions using the installed UI and local Chromium."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from playwright.sync_api import expect, sync_playwright
from paw.core.scoring import _score_metadata
import paw.web

STATIC = Path(paw.web.__file__).parent / 'static'
CASES = [(_score_metadata(score, {}, 'default'), text) for score, text in
         [(0.0, 'Inconclusiva'), (.60, 'Account sospetto o compromesso'),
          (.90, 'Infrastruttura probabilmente malevola')]]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        assets = {'/': ('index.html', 'text/html'), '/assets/app.js': ('app.js', 'text/javascript'),
                  '/assets/app.css': ('app.css', 'text/css')}
        if self.path in assets:
            filename, kind = assets[self.path]
            body = (STATIC / filename).read_bytes()
        else:
            kind = 'application/json'
            if self.path.startswith('/api/cases?'):
                data = {'total': len(CASES), 'cases': [{'case_id': f'case-{i}', 'status':'completed'}
                                                       for i in range(len(CASES))]}
            elif self.path.startswith('/api/cases/case-'):
                i = int(self.path.rsplit('-', 1)[1])
                data = {'case_id': f'case-{i}', 'score': CASES[i][0], 'status':'completed'}
            else:
                data = {'jobs': []}
            body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header('Content-Type', kind + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                try:
                    page = browser.new_page()
                    page.goto(f'http://127.0.0.1:{server.server_port}/')
                    for i, (_, expected) in enumerate(CASES):
                        page.locator('.case-row').nth(i).click()
                        expect(page.locator('#case-decision')).to_have_text(expected)
                        print(expected)
                finally:
                    browser.close()
        finally:
            server.shutdown()
            thread.join()


if __name__ == '__main__':
    main()
