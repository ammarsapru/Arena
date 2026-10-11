"""Inert marker oracle in an isolated browser. Blocks all network access."""
import json
import sys
from playwright.sync_api import sync_playwright

data=json.load(sys.stdin)
with sync_playwright() as p:
    from pathlib import Path
    browser=p.chromium.launch(**({} if Path(p.chromium.executable_path).exists() else {'channel':'chrome'}))
    page=browser.new_page()
    page.route('**/*',lambda route:route.abort())
    page.set_content(data['html'],wait_until='load',timeout=5000)
    page.wait_for_timeout(60)
    print(json.dumps({'executed':page.evaluate('window.__arena_xss === 1')}))
    browser.close()
