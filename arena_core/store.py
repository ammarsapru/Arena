"""Durable run evidence, optional MongoDB mirror, resumable SSE sequence."""
import json
import os
import sqlite3
import threading
import time
from pathlib import Path

class EventStore:
    def __init__(self,directory):
        Path(directory).mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(str(Path(directory)/'runs.sqlite3'),check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT, event TEXT, at REAL)')
        self.db.commit();self.lock=threading.RLock();self.mongo=None;self.mongo_status='not configured'
        if os.environ.get('MONGODB_URI'):
            try:
                from pymongo import MongoClient
                client=MongoClient(os.environ['MONGODB_URI'],serverSelectionTimeoutMS=2000)
                client.admin.command('ping');self.mongo=client[os.environ.get('MONGODB_DATABASE','arena')]['events'];self.mongo_status='connected'
            except Exception as exc:self.mongo_status='unavailable: '+type(exc).__name__

    def emit(self,run,type,**payload):
        event={'type':type,'run_id':run,'timestamp':time.time(),**payload}
        with self.lock:
            cur=self.db.execute('INSERT INTO events(run,event,at) VALUES(?,?,?)',(run,json.dumps(event),time.time()));self.db.commit()
            event['seq']=cur.lastrowid
        if self.mongo is not None:
            try:self.mongo.insert_one(dict(event))
            except Exception:self.mongo_status='mirror write failed; local evidence retained'
        return event

    def events(self,run,after=0):
        with self.lock:rows=self.db.execute('SELECT seq,event FROM events WHERE run=? AND seq>? ORDER BY seq LIMIT 500',(run,after)).fetchall()
        return [dict(json.loads(row[1]),seq=row[0]) for row in rows]

    def runs(self):
        with self.lock:rows=self.db.execute('SELECT run,COUNT(*),MAX(at) FROM events GROUP BY run ORDER BY MAX(at) DESC LIMIT 30').fetchall()
        return [{'id':r[0],'events':r[1],'updated_at':r[2]} for r in rows]
