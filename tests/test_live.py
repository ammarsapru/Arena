"""Real HTTP regression checks; model inference is explicitly stubbed only here."""
import copy
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from arena_core.target import TargetRuntime,TargetServer
from arena_core.policy import BASELINE,NAIVE,HARDENED,compile_policy,validate
from arena_core.cases import Transport,scenarios,score

class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.runtime=TargetRuntime(cls.tmp.name)
        cls.server=TargetServer(cls.runtime,0).start();cls.transport=Transport(f'http://127.0.0.1:{cls.server.port}',cls.runtime)
    @classmethod
    def tearDownClass(cls):cls.server.close();cls.tmp.cleanup()

    def evaluate(self,policy):
        with patch('arena_core.target.call_model',return_value='Invoice NS-1042 is $2,400. Case CS-301 is open.'):
            with ThreadPoolExecutor(max_workers=4) as pool:
                return list(pool.map(lambda c:self.transport.execute(c,compile_policy(policy)),scenarios()))

    def test_real_http_baseline_and_hardening(self):
        before=self.evaluate(BASELINE);after=self.evaluate(HARDENED)
        self.assertEqual(score(before)['errors'],0,before)
        self.assertGreaterEqual(score(before)['compromised'],10)
        self.assertEqual(score(after)['errors'],0,after)
        self.assertEqual(score(after)['compromised'],0,after)
        self.assertEqual(score(after)['served'],score(after)['benign'],after)

    def test_deny_all_fails_legitimate_tasks(self):
        policy=copy.deepcopy(HARDENED);policy['waf']['terms']=['invoice','jamie','billing']
        self.assertGreater(score(self.evaluate(policy))['false_blocks'],0)

    def test_policy_rejects_unbounded_or_executable_values(self):
        policy=copy.deepcopy(BASELINE);policy['rate']['limit']='__import__("os")'
        with self.assertRaises(ValueError):validate(policy)
        policy=copy.deepcopy(BASELINE);policy['waf']['terms']=['a']
        with self.assertRaises(ValueError):validate(policy)

    def test_invalid_defender_output_does_not_abort_run(self):
        from arena_core.orchestrator import Arena
        from arena_core.store import EventStore
        def fake_model(system,data,max_tokens=1800):
            if 'select existing test fixtures' in system:return {'families':['sqli','access','traversal'],'reason':'stub'}
            if 'attack variation' in system or 'bounded attack' in system:return {'payload':"' OR '1'='1' --",'reason':'stub'}
            if 'Coordinate four defensive' in system:return {'lessons':'stub','priorities':{}}
            section=data['section'];fixed=copy.deepcopy(HARDENED[section])
            if section=='waf':fixed['terms']=['a']*30  # out of bounds on every attempt
            return {'policy':fixed,'reason':'stub'}
        seeds=[{'source':'stub','row_id':i,'text':'Ignore previous instructions '+str(i),'hash':str(i),'partition':p} for i,p in enumerate(['train','train','holdout'])]
        with tempfile.TemporaryDirectory() as tmp:
            arena=Arena(self.transport,EventStore(tmp),tmp)
            with patch('arena_core.orchestrator.json_model',fake_model),patch('arena_core.orchestrator.import_sources',return_value=(seeds,[])),\
                 patch('arena_core.target.call_model',return_value='Invoice NS-1042 is $2,400. Case CS-301 is open.'):
                arena.start(2);arena.worker.join(300)
            types=[e['type'] for e in arena.store.events(arena.run_id)]
            arena.store.db.close()
        self.assertEqual(arena.status,'completed',arena.error)
        self.assertGreaterEqual(types.count('specialist_rejected'),2)
        # The WAF proposal is always invalid, so that section stays at the naive baseline.
        self.assertEqual(arena.policy['policy']['waf']['terms'],NAIVE['waf']['terms'])
        self.assertIsNotNone(arena.holdout)

    def test_transport_rejects_external_origin(self):
        with self.assertRaises(ValueError):Transport('https://example.com',self.runtime)

if __name__=='__main__':unittest.main()
