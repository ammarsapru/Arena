"""Run a real Luminal-backed arena and save measured evidence. Uses API credits."""
import json
import logging
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arena_core.target import TargetRuntime,TargetServer
from arena_core.cases import Transport
from arena_core.orchestrator import Arena
from arena_core.store import EventStore

logging.getLogger('werkzeug').setLevel(logging.ERROR)
root=Path(__file__).resolve().parents[1]
runtime=TargetRuntime(root/'.arena-data/check-target')
target=TargetServer(runtime,0).start()
arena=Arena(Transport(f'http://127.0.0.1:{target.port}',runtime),EventStore(root/'.arena-data'),root/'.arena-data')
try:
    run=arena.start(int(sys.argv[1]) if len(sys.argv)>1 else 1)
    cursor=0
    while arena.worker.is_alive():
        for event in arena.store.events(run,cursor):
            cursor=event['seq']
            if event['type'] in ('agent_started','agent_completed','agent_failed'):
                print(event['type'],event['task']['name'],flush=True)
            elif event['type']=='attack_completed' and event['result']['outcome']=='error':
                print('REQUEST ERROR',event['result'],flush=True)
            elif event['type']=='specialist_rejected':
                print('REJECTED',event['section'],event['error'],flush=True)
            elif event['type'] in ('datasets_loaded','round_scored','candidate_verified','holdout_scored','run_failed'):
                recorded_round=event.get('round')
                summary_score=event.get('score') or (recorded_round.get('score') if isinstance(recorded_round,dict) else None)
                print(json.dumps({'type':event['type'],'score':summary_score,'accepted':event.get('accepted'),'verdict':event.get('verdict'),'datasets':event.get('datasets'),'error':event.get('error')}),flush=True)
        arena.worker.join(.5)
    result=arena.snapshot()
    (root/'.artifacts/live-check.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'status':result['status'],'error':result['error'],'rounds':[r['score'] for r in result['rounds']],'holdout':{k:v for k,v in (result['holdout'] or {}).items() if k!='results'},'tasks':len(result['tasks'])}),flush=True)
finally:
    if arena.worker and arena.worker.is_alive():
        arena.stop.set();arena.worker.join(timeout=70)
    target.close()
