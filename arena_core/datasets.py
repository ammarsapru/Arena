"""Fetch and cache real rows with source provenance; split before agent mutation."""
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen, Request

SOURCES=['deepset/prompt-injections','Lakera/gandalf_ignore_instructions','jayavibhav/prompt-injection']

def import_sources(directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    records=[];manifest=[]
    for source in SOURCES:
        path=directory/(source.replace('/','--')+'.json')
        try:
            if path.exists(): raw=path.read_bytes()
            else:
                query=urlencode({'dataset':source,'config':'default','split':'train'})
                with urlopen(Request('https://datasets-server.huggingface.co/first-rows?'+query,headers={'User-Agent':'Arena-local-evaluation/1.0'}),timeout=20) as response:raw=response.read(2_000_000)
                path.write_bytes(raw)
            data=json.loads(raw)
            count=0
            for item in data['rows']:
                row=item['row'];text=str(row.get('text','')).strip()
                if not text:continue
                # Lakera is a noisy attack-seed collection, not a binary classifier corpus.
                if source.startswith('Lakera') or row.get('label')==1:
                    digest=hashlib.sha256(' '.join(text.lower().split()).encode()).hexdigest()
                    records.append({'source':source,'row_id':item['row_idx'],'text':text[:2200],'hash':digest,'partition':'holdout' if int(digest[:8],16)%5==0 else 'train'})
                    count+=1
            manifest.append({'source':source,'rows_fetched':len(data['rows']),'attack_seeds':count,'snapshot_sha256':hashlib.sha256(raw).hexdigest(),'status':'imported'})
        except Exception as exc:
            manifest.append({'source':source,'status':'unavailable','error':type(exc).__name__})
    unique={}
    for r in records:unique.setdefault(r['hash'],r)
    return list(unique.values()),manifest
