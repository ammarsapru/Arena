"""Restricted policy compiler: model text is data, never executable Python."""
import copy
import hashlib
import json
from pathlib import Path

BASELINE = {
 'rate': {'limit': 0, 'window': 60, 'login_limit': 0},
 'waf': {'terms': [], 'parameterize_sql': False, 'escape_html': False, 'safe_paths': False},
 'access': {'enforce_scope': False, 'filter_retrieval': False, 'require_csrf': False, 'uniform_reset': False},
 'crypto': {'verify_signature': False, 'check_expiry': False},
}
# The posture a typical vibe-coded app actually ships with: a naive keyword blocklist that
# feels safe, a loose rate cap, and no real authorization, token checks or output encoding.
# Every one of these is bypassable, which is what makes the arms race genuine rather than staged.
NAIVE = {
 'rate': {'limit': 150, 'window': 60, 'login_limit': 0},
 'waf': {'terms': ['<script>', 'drop table', 'union select'], 'parameterize_sql': False, 'escape_html': False, 'safe_paths': False},
 'access': {'enforce_scope': False, 'filter_retrieval': False, 'require_csrf': False, 'uniform_reset': False},
 'crypto': {'verify_signature': False, 'check_expiry': False},
}
HARDENED = {
 'rate': {'limit': 80, 'window': 60, 'login_limit': 4},
 'waf': {'terms': [], 'parameterize_sql': True, 'escape_html': True, 'safe_paths': True},
 'access': {'enforce_scope': True, 'filter_retrieval': True, 'require_csrf': True, 'uniform_reset': True},
 'crypto': {'verify_signature': True, 'check_expiry': True},
}
FILENAMES = {'rate':'rate_limiter.py','waf':'waf_filter.py','access':'access_control.py','crypto':'crypto_policy.py'}

def validate(policy):
    if not isinstance(policy, dict) or set(policy) != set(BASELINE):
        raise ValueError('Expected the four policy sections')
    out = copy.deepcopy(policy)
    for section, defaults in BASELINE.items():
        if not isinstance(out[section], dict) or set(out[section]) != set(defaults):
            raise ValueError(f'Invalid keys for {section}')
        for key, value in out[section].items():
            if key == 'terms':
                if not isinstance(value, list) or len(value) > 24 or any(not isinstance(t,str) or not 3 <= len(t) <= 100 for t in value):
                    raise ValueError('Terms must be at most 24 bounded literal strings')
                out[section][key] = list(dict.fromkeys(t.lower() for t in value))
            elif type(defaults[key]) is bool:
                if type(value) is not bool: raise ValueError('Expected boolean')
            else:
                lo, hi = {'limit':(0,200),'window':(1,120),'login_limit':(0,20)}[key]
                if type(value) is not int or not lo <= value <= hi: raise ValueError('Invalid numeric policy value')
    return out

def compile_policy(policy):
    p = validate(policy)
    sources = {
      'rate_limiter.py': f'''# Compiled policy. True = allow.
def allow(ip, acct, now, hist):
    limit, window, login_limit = {p['rate']['limit']}, {p['rate']['window']}, {p['rate']['login_limit']}
    requests = sum(now - t < window for t in hist.get(ip, []))
    failures = sum(now - t < window for t in hist.get("login:" + acct, []))
    return (not limit or requests < limit) and (not acct or not login_limit or failures < login_limit)
''',
      'waf_filter.py': f'''# Compiled policy. True = block.
OPTIONS = {p['waf']!r}
def inspect(req):
    text = req.lower()
    return any(term in text for term in OPTIONS["terms"])
''',
      'access_control.py': f'''# Permissions are immutable server facts.
OPTIONS = {p['access']!r}
def authorize(session, resource):
    return bool(session) and (not OPTIONS["enforce_scope"] or resource["permitted"])
''',
      'crypto_policy.py': f'''# Crypto checks are supplied by the trusted runtime.
OPTIONS = {p['crypto']!r}
def verify(token):
    if OPTIONS["verify_signature"] and not token["signature_valid"]:
        raise ValueError("Invalid signature")
    if OPTIONS["check_expiry"] and not token["expiry_valid"]:
        raise ValueError("Expired token")
    return token["claims"]
'''
    }
    functions = {}
    for name, code in sources.items():
        namespace = {'__builtins__': {'sum':sum,'any':any,'bool':bool,'ValueError':ValueError}}
        # Templates are trusted, every inserted value was validated and repr-encoded.
        exec(compile(code, name, 'exec'), namespace)
        functions[name] = namespace
    version = hashlib.sha256(json.dumps(p,sort_keys=True).encode()).hexdigest()[:12]
    return {'policy':p,'files':sources,'functions':functions,'version':version}

def save_version(compiled, root):
    directory = Path(root) / compiled['version']
    directory.mkdir(parents=True, exist_ok=True)
    for filename, code in compiled['files'].items():
        (directory / filename).write_text(code, encoding='utf-8')
    (directory / 'policy.json').write_text(json.dumps(compiled['policy'], indent=2), encoding='utf-8')
