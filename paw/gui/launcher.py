"""Local workbench launcher. Own the listening socket before opening a browser."""
import os
from pathlib import Path
import socket
import threading
import time
import urllib.request
import webbrowser

def main(port=8765, data_dir=None, open_browser=True, debug=False):
    if not 1 <= port <= 65535: raise ValueError('Port must be between 1 and 65535')
    root = Path(data_dir or os.environ.get('PAW_DATA_DIR', os.getcwd())).resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.environ['PAW_DATA_DIR'] = str(root)
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        # No port reuse: a different service must never be mistaken for PAW.
        listener.bind(('127.0.0.1',port))
        listener.listen(128)
        url = f'http://127.0.0.1:{port}'
        print(f'PAW workspace: {url}\nData: {root}\nStop with Ctrl+C.')
        import uvicorn
        from ..web.api import app
        server = uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,
            timeout_graceful_shutdown=5,log_level='debug' if debug else 'info'))
        if open_browser:
            def show():
                client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                for _ in range(100):
                    try:
                        with client.open(url+'/health',timeout=.5) as response:
                            if response.status == 200:
                                webbrowser.open(url)
                                return
                    except OSError: time.sleep(.1)
            threading.Thread(target=show,daemon=True).start()
        server.run(sockets=[listener])
