"""Verify the preview uses the user's Arena Command.html without redesigning it."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / '.artifacts'

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass

def main():
    assert (ROOT / 'Arena Command.html').read_bytes() == (ROOT / 'mockup/index.html').read_bytes()
    ARTIFACTS.mkdir(exist_ok=True)
    server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(ROOT / 'mockup')))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={'width':1440,'height':1100}, color_scheme='light', reduced_motion='reduce')
            page.on('pageerror', lambda error: errors.append(str(error)))
            assert page.goto(f'http://127.0.0.1:{server.server_port}/', wait_until='networkidle').status == 200
            assert page.locator('.row2 .dark-card').count() == 2
            assert page.locator('.stage').first.bounding_box()['height'] >= 400
            assert page.locator('.row3 > .card').count() == 3
            assert page.locator('#files .ft').count() == 4
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.screenshot(path=str(ARTIFACTS / 'arena-command-restored-desktop.png'), full_page=True)
            page.locator('#step').click()
            assert page.locator('#coreN').inner_text() == '2'
            page.get_by_role('button', name='R4', exact=True).click()
            assert page.locator('#coreN').inner_text() == '4'
            page.locator('.ft[data-f="crypto_policy.py"]').click()
            assert 'jwt.decode' in page.locator('#code').inner_text()
            page.emulate_media(color_scheme='dark')
            page.screenshot(path=str(ARTIFACTS / 'arena-command-restored-dark.png'), full_page=True)
            mobile = browser.new_page(viewport={'width':390,'height':844}, color_scheme='light', reduced_motion='reduce')
            mobile.on('pageerror', lambda error: errors.append(str(error)))
            mobile.goto(f'http://127.0.0.1:{server.server_port}/', wait_until='networkidle')
            assert mobile.evaluate('document.documentElement.scrollWidth <= innerWidth')
            mobile.screenshot(path=str(ARTIFACTS / 'arena-command-restored-mobile.png'), full_page=True)
            assert not errors, errors
            browser.close()
            print('PASS: exact original source, large hero panels, supporting row, code tabs, round selection, responsive layout; no browser errors.')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

if __name__ == '__main__':
    main()
