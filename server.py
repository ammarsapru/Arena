"""Arena control plane. Starts the isolated synthetic target on localhost:5002."""
import atexit
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
import httpx
from flask import Flask, Response, jsonify, request, send_from_directory, session
from arena_core.target import TargetRuntime,TargetServer,DEMO_PASSWORD
from arena_core.cases import Transport
from arena_core.store import EventStore
from arena_core.orchestrator import Arena
from arena_core.policy import compile_policy,NAIVE,HARDENED
from model import CONFIG

ROOT=Path(__file__).parent
app=Flask(__name__)
app.secret_key=secrets.token_bytes(32)
app.config.update(MAX_CONTENT_LENGTH=32_768,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict')
_runtime=None
_target=None
_arena=None
_init_lock=threading.Lock()
CONTROL_TOKEN=secrets.token_urlsafe(24)


def initialize():
    global _runtime,_target,_arena
    with _init_lock:
        if _arena is None:
            data=ROOT/'.arena-data'
            _runtime=TargetRuntime(data/'target')
            _target=TargetServer(_runtime,int(os.environ.get('ARENA_TARGET_PORT','5002'))).start()
            store=EventStore(data)
            _arena=Arena(Transport(f'http://127.0.0.1:{_target.port}',_runtime),store,data)
    return _arena


@app.before_request
def local_only():
    if request.remote_addr not in ('127.0.0.1','::1'):
        return jsonify(error='Local development lab only'),403
    if request.method in ('POST','PUT','DELETE') and request.headers.get('X-Arena-Control')!=CONTROL_TOKEN:
        return jsonify(error='Missing control-session token; reload the dashboard'),403


@app.get('/')
@app.get('/mockup/')
@app.get('/mockup/index.html')
def index():
    # Preserve the user's markup, CSS, canvas geometry and layout. Replace sample JS.
    html=(ROOT/'Arena Command.html').read_text(encoding='utf-8')
    start=html.index('<script>');end=html.index('</script>',start)+len('</script>')
    html=html[:start]+'<script src="/web/arena.js"></script><script src="/web/rings-original.js"></script>'+html[end:]
    html=html.replace(' · sample data, mockup only',' · real HTTP evaluation')
    html=html.replace('127.0.0.1:5001','127.0.0.1:5002')
    html=html.replace('Run next round','Start live run')
    html=html.replace('</head>','<link rel="stylesheet" href="/web/live.css"></head>',1)
    html=html.replace('<span class="chip"><span class="dot"></span>deepseek-v4.1-flash · Luminal</span>',
        '<button class="btn dark" id="openCompany">Company assistant</button><button class="btn" id="liveAttack">🤖 Live attack browsers</button><button class="btn" id="theaterBtn">Attack theater</button><label class="tag">Rounds <select id="roundCount"><option selected>2</option><option>3</option><option>4</option><option>5</option><option>6</option><option>7</option><option>8</option></select></label><button class="btn" id="stopRun" hidden>Stop</button><span class="chip"><span class="dot"></span>DeepSeek · Luminal</span>')
    html=html.replace('<section class="kpis"','<div id="liveStatus" role="status">Connecting to local arena…</div><section class="kpis"',1)
    return html


@app.get('/favicon.ico')
def favicon():return '',204


@app.get('/web/<path:name>')
def assets(name):return send_from_directory(ROOT/'web',name)


@app.get('/theater')
def theater():return send_from_directory(ROOT/'web','theater.html')


@app.get('/api/state')
def state():
    arena=initialize()
    return jsonify(**arena.snapshot(),control_token=CONTROL_TOKEN,history=arena.store.runs())


@app.post('/api/runs')
def start_run():
    arena=initialize()
    try:
        run=arena.start((request.get_json(silent=True) or {}).get('rounds',2))
        return jsonify(run_id=run),202
    except ValueError as exc:return jsonify(error=str(exc)),409


@app.post('/api/browsers')
def browsers():
    # Launch real, tiled Chrome windows that each drive one attack through the live sample-site
    # UI — against a vulnerable sandbox first, then the hardened app — so the breach and the fix
    # are both watchable in an actual browser.
    initialize()
    body=request.get_json(silent=True) or {}
    families=[f for f in (body.get('families') or ['sqli','access','traversal']) if isinstance(f,str)][:4]
    naive=_runtime.new_context(compile_policy(NAIVE))
    hardened=_runtime.new_context(compile_policy(HARDENED))
    args=[sys.executable,str(ROOT/'scripts/attack_browsers.py'),'--target',f'http://127.0.0.1:{_target.port}',
          '--naive',naive,'--hardened',hardened,'--families',','.join(families)]
    if body.get('headless'):args.append('--headless')
    try:
        proc=subprocess.Popen(args,cwd=str(ROOT))
    except Exception as exc:
        return jsonify(error='Could not launch browsers: '+type(exc).__name__),500
    return jsonify(ok=True,families=families,pid=proc.pid)


@app.post('/api/stop')
def stop_run():
    arena=initialize()
    if arena.status=='running':arena.status='stopping';arena.stop.set()
    return jsonify(status=arena.status)


@app.get('/api/events/<run_id>')
def events(run_id):
    arena=initialize()
    try:after=int(request.headers.get('Last-Event-ID',request.args.get('after',0)))
    except ValueError:return jsonify(error='Invalid event sequence'),400
    def stream():
        cursor=after
        while True:
            batch=arena.store.events(run_id,cursor)
            for event in batch:
                cursor=event['seq'];yield f'id: {cursor}\ndata: {json.dumps(event)}\n\n'
            if arena.run_id!=run_id or arena.status not in ('running','stopping'):
                if not batch:break
            if not batch:yield ': heartbeat\n\n'
            time.sleep(.3)
    return Response(stream(),mimetype='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})


@app.get('/api/runs/<run_id>')
def export_run(run_id):
    arena=initialize();items=[];cursor=0
    while True:
        batch=arena.store.events(run_id,cursor)
        if not batch:break
        items+=batch;cursor=batch[-1]['seq']
    return jsonify(run_id=run_id,events=items)


def target_request(path,body):
    initialize()
    with httpx.Client(base_url=f'http://127.0.0.1:{_target.port}',timeout=65,trust_env=False,follow_redirects=False) as client:
        headers={}
        if session.get('target_sid'):headers['X-Session']=session['target_sid']
        response=client.post(path,json=body,headers=headers)
        if path=='/login' and response.status_code==200:session['target_sid']=response.cookies.get('arena_session')
        try:return jsonify(response.json()),response.status_code
        except ValueError:return jsonify(error='Unexpected target response'),502


@app.post('/api/company/login')
def company_login():
    body=request.get_json(silent=True) or {}
    session.clear()
    return target_request('/login',{'username':body.get('username'),'password':body.get('password',DEMO_PASSWORD)})


@app.post('/api/company/chat')
def company_chat():
    if not session.get('target_sid'):return jsonify(error='Select an identity first'),401
    return target_request('/chat',request.get_json(silent=True) or {})


@app.get('/api/company/identities')
def identities():
    initialize()
    with _runtime.default['lock']:
        records=_runtime.default['db'].execute('SELECT id,display_name,role,organization_id,department_id,clearance FROM users').fetchall()
    return jsonify(identities=[dict(row) for row in records])


@app.errorhandler(Exception)
def error(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc,HTTPException):return jsonify(error=exc.description),exc.code
    return jsonify(error='Controller error: '+type(exc).__name__),500


def shutdown():
    if _arena:_arena.stop.set()
    if _target:_target.close()


if __name__=='__main__':
    initialize()
    atexit.register(shutdown)
    print('Arena Command: http://127.0.0.1:5001 | target: http://127.0.0.1:5002',flush=True)
    app.run(host='127.0.0.1',port=int(os.environ.get('ARENA_PORT','5001')),threaded=True,debug=False)
