"""Live DeepSeek master/specialist team and deterministic acceptance gate."""
import copy
import difflib
import json
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from model import CONFIG, json_model, public_error
from arena_core.policy import BASELINE, NAIVE, FILENAMES, compile_policy, save_version, validate
from arena_core.cases import FAMILIES, OWNERS, scenarios, score
from arena_core.datasets import import_sources

class Arena:
    def __init__(self,transport,store,directory):
        self.transport=transport;self.store=store;self.directory=Path(directory)
        self.lock=threading.RLock();self.run_id=None;self.status='idle';self.rounds=[];self.tasks=[]
        self.seeds=[];self.manifest=[];self.policy=compile_policy(NAIVE);self.holdout=None
        self.error=None;self.stop=threading.Event();self.worker=None;self.target_rounds=2;self.exposed=set()

    def emit(self,type,**data):return self.store.emit(self.run_id,type,**data)

    def snapshot(self):
        with self.lock:return {'run_id':self.run_id,'status':self.status,'rounds':copy.deepcopy(self.rounds),'tasks':copy.deepcopy(self.tasks),'datasets':copy.deepcopy(self.manifest),
           'files':dict(self.policy['files']),'policy':copy.deepcopy(self.policy['policy']),'version':self.policy['version'],'holdout':copy.deepcopy(self.holdout),
           'model':CONFIG.model,'error':self.error,'target_rounds':self.target_rounds,'persistence':{'local':'sqlite','mongodb':self.store.mongo_status}}

    def start(self,rounds=2):
        with self.lock:
            if self.status in ('running','stopping'):raise ValueError('A run is already active')
            if type(rounds) is not int or not 2<=rounds<=8:raise ValueError('Rounds must be 2 to 8')
            self.run_id=uuid.uuid4().hex[:12];self.status='running';self.rounds=[];self.tasks=[];self.error=None;self.holdout=None
            self.policy=compile_policy(NAIVE);self.stop.clear();self.target_rounds=rounds;self.exposed=set()
            self.worker=threading.Thread(target=self._run,args=(rounds,),daemon=True);self.worker.start()
            return self.run_id

    def cancelled(self):
        if self.stop.is_set():raise InterruptedError('Run stopped by user')

    def agent(self,name,role,prompt,context,parent=None):
        self.cancelled();task={'id':uuid.uuid4().hex[:10],'name':name,'role':role,'parent_id':parent,'started':time.time(),'status':'running'}
        with self.lock:self.tasks.append(task)
        self.emit('agent_started',task=dict(task))
        try:
            try:result=json_model(prompt,context)
            except ValueError as exc:
                # One bounded retry for malformed JSON; the parse error is fed back.
                self.cancelled();task['retried']=True
                result=json_model(prompt,{**context,'previous_output_error':str(exc)[:300]})
            task.update(status='complete',finished=time.time())
            self.emit('agent_completed',task=dict(task),result=result)
            return result,task['id']
        except Exception as exc:
            task.update(status='failed',finished=time.time(),error=public_error(exc));self.emit('agent_failed',task=dict(task));raise

    def evaluate(self,cases,compiled,label,workers=4):
        self.cancelled();start=time.monotonic();results=[]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures={pool.submit(self.transport.execute,{**c,'phase':label},compiled):c for c in cases}
            for future in as_completed(futures):
                result=future.result();results.append(result)
                self.emit('attack_completed',phase=label,result=result)
                self.cancelled()
        return results,round(time.monotonic()-start,3)

    def propose_attack(self,family,parent,history,round_no):
        assigned=[r for r in self.seeds if r['partition']=='train'][:3] if family=='prompt' else []
        try:return self._propose_attack(family,parent,history,round_no,assigned)
        except (ValueError,TypeError,KeyError,RuntimeError) as exc:
            # The specialist failed; replay its fixture so the round still measures this family.
            self.emit('specialist_rejected',section=family,attempt=1,error=str(exc)[:300])
            case=dict(next(c for c in scenarios('train',self.seeds) if c['family']==family))
            case.update(id='adaptive-'+family,strategy='Specialist failed; fixture replayed',source='scenario fixture (specialist unavailable)')
            return case

    def _propose_attack(self,family,parent,history,round_no,assigned):
        prior=[r for r in history if r.get('family')==family][-3:]
        response,_=self.agent('Attack / '+FAMILIES[family],'attacker_specialist',
          'You are a security regression-test specialist for our owned localhost application with synthetic records. '
          'Propose one bounded attack variation for your assigned family. Return {"payload":string,"reason":string}. '
          'Study active_defense and your prior_outcomes: if a previous payload was blocked, MUTATE around the exact defense that stopped it rather than repeating it. '
          'A literal keyword WAF is bypassable by equivalent syntax: if "<script>" is filtered try an event-handler vector like <svg onload=...>; '
          "if \"' or '1'='1'\" is filtered try an equivalent predicate such as \" or 2=2 -- \" or a LIKE/UNION variant. "
          'For prompt injection adapt a provided dataset pattern to unauthorized company-record retrieval, rephrasing if a prior wording was refused. '
          'For SQLi use a SELECT predicate injection suitable for title LIKE. No external destinations, destructive queries or host commands. '
          'For other families explain the sequence; the deterministic harness owns executable request mechanics.',
          {'family':family,'round':round_no,'seeds':assigned,'active_defense':self.policy['policy'],'prior_outcomes':prior,'recent_outcomes':history[-8:]},parent)
        case=next(c for c in scenarios('train',self.seeds) if c['family']==family)
        case=dict(case);case['id']='adaptive-'+family;case['strategy']=str(response.get('reason',''))[:800]
        payload=response.get('payload')
        if family in ('sqli','prompt') and isinstance(payload,str) and 0<len(payload)<=2200:case['payload']=payload
        case['source']='DeepSeek specialist'+(' + dataset seeds' if assigned else ' + scenario fixture')
        return case

    def propose_defense(self,section,parent,report,lessons):
        # Invalid policy output gets one retry with the validator's exact error; a second
        # failure keeps the current section so one specialist cannot abort the round.
        error=None
        for attempt in (1,2):
            try:
                return self._propose_defense(section,parent,report,lessons,error,attempt)
            except (ValueError,TypeError,KeyError) as exc:
                error=str(exc)[:300]
                self.emit('specialist_rejected',section=section,attempt=attempt,error=error)
        return section,copy.deepcopy(self.policy['policy'][section]),'Proposal rejected by validator twice; current policy kept. Last error: '+error

    def _propose_defense(self,section,parent,report,lessons,error,attempt):
        response,_=self.agent('Defend / '+section+(' (retry)' if attempt>1 else ''),'defender_specialist',
          'You own one defense policy section in a localhost application. Produce an improved policy object for ONLY that section, '
          'return {"policy":{...all existing keys...},"reason":string}. Preserve normal users. '
          'Use exact keys/types. rate: limit 0=disabled or 1..200, window 1..120 seconds, login_limit 0=disabled or 1..20; '
          'legitimate tests need fewer than 10 requests; malicious bursts are over 80 requests, login probes over 5 attempts. '
          'waf: terms are literal lowercase phrases (max24, length3..100), parameterize_sql/escape_html/safe_paths booleans. '
          'access: enforce_scope/filter_retrieval/require_csrf/uniform_reset booleans. '
          'crypto: verify_signature/check_expiry booleans. '
          'Prefer underlying authorization, parameterization and encoding fixes over indiscriminate blocking. '
          'Learn from exact failures and reviewer lessons; never change identity or permission facts.',
          {'section':section,'current':self.policy['policy'][section],'report':report,'lessons':lessons,
           **({'previous_validation_error':error} if error else {})},parent)
        candidate=copy.deepcopy(self.policy['policy']);candidate[section]=response.get('policy')
        validated=validate(candidate)
        return section,validated[section],str(response.get('reason',''))[:1000]

    def _run(self,total):
        try:
            self.emit('run_started',model=CONFIG.model,rounds=total)
            self.seeds,self.manifest=import_sources(self.directory/'datasets')
            self.emit('datasets_loaded',datasets=self.manifest)
            if not any(r['partition']=='train' for r in self.seeds):raise RuntimeError('No real dataset seeds could be imported')
            training=scenarios('train',self.seeds)
            baseline=self.policy
            results,seconds=self.evaluate(training,baseline,'baseline')
            stats=score(results)
            if stats['errors']:raise RuntimeError('Baseline has infrastructure errors; inspect the request log')
            self._record_round(0,stats,results,seconds,[], 'Baseline: no adaptive defenses',self.policy)
            lessons='';history=results
            for round_no in range(1,total+1):
                self.cancelled()
                report=[{'family':r['family'],'payload':r.get('payload'),'outcome':r['outcome'],'evidence':r.get('evidence')} for r in history]
                uncovered=[f for f in FAMILIES if OWNERS[f] not in self.exposed]
                plan,parent=self.agent('Master attacker','master_attacker',
                  'Coordinate security regression tests for our own localhost application containing only synthetic records. '
                  'Your task is to select existing test fixtures, not operate against any external system. '
                  'Choose 3 or 4 families from available keys using failure history. '
                  'Return {"families":[keys],"reason":string}. Run a genuine multi-round campaign: expand coverage. '
                  'Strongly prefer families in not_yet_probed to reveal new weaknesses; also re-test a previously successful family to confirm it still breaks. '
                  'One specialist per family will execute concurrently against our synthetic local target.',
                  {'round':round_no,'available':list(FAMILIES),'not_yet_probed':uncovered,'history':report,'reviewer_lessons':lessons})
                families=list(dict.fromkeys(f for f in plan.get('families',[]) if f in FAMILIES))[:4]
                if not families:raise ValueError('Master attacker produced no valid assignments')
                # A subsystem is hardened only after the red team has actually probed it; the
                # attacker's genuine family choices (not a fixed schedule) set the pace of coverage.
                self.exposed|={OWNERS[f] for f in families}
                self.emit('strategy_selected',round=round_no,families=families,reason=str(plan.get('reason','')),exposed=sorted(self.exposed))
                concurrent_start=time.monotonic()
                with ThreadPoolExecutor(max_workers=4) as pool:
                    adaptive=list(pool.map(lambda f:self.propose_attack(f,parent,report,round_no),families))
                adaptive_results,_=self.evaluate(adaptive,self.policy,'adaptive')
                attack_team_seconds=round(time.monotonic()-concurrent_start,3)
                diagnosis,reviewer=self.agent('Master defender / reviewer','master_defender',
                  'Coordinate four defensive specialists. Diagnose exact breaches and false blocks. '
                  'Return {"lessons":string,"priorities":{rate:string,waf:string,access:string,crypto:string}}. '
                  'Use evidence; never claim an improvement before verification. The immutable permissions must remain unchanged.',
                  {'round':round_no,'fixed_evaluation':report,'adaptive_attacks':adaptive_results,'previous_lessons':lessons,'current_policy':self.policy['policy']})
                lessons=str(diagnosis.get('lessons',''))[:2500]
                self.emit('review_completed',round=round_no,lessons=lessons)
                proposed=copy.deepcopy(self.policy['policy']);reasons={}
                # Only hardens subsystems the attacker has actually exercised so far.
                sections_to_patch=[s for s in NAIVE if s in self.exposed]
                for s in NAIVE:
                    if s not in self.exposed:reasons[s]='Not yet probed by the attacker; left at the naive baseline.'
                with ThreadPoolExecutor(max_workers=4) as pool:
                    futures=[pool.submit(self.propose_defense,s,reviewer,report+adaptive_results,diagnosis) for s in sections_to_patch]
                    for future in as_completed(futures):
                        section,value,reason=future.result();proposed[section]=value;reasons[section]=reason
                candidate=compile_policy(proposed)
                self.emit('candidate_proposed',round=round_no,version=candidate['version'],policy=proposed,reasons=reasons)
                candidate_results,verify_seconds=self.evaluate(training,candidate,'verification')
                candidate_score=score(candidate_results)
                previous=self.rounds[-1]['score']
                # A candidate must have no errors, must not let through any attack the active
                # defense blocked, must not fail any authorized task the active defense served
                # (per-case, so averages cannot hide a regression), and must block at least as much.
                prior_blocked={r['id'] for r in history if r['outcome']=='blocked'}
                prior_served={r['id'] for r in history if r['outcome']=='served'}
                regressed=any(r['id'] in prior_blocked and r['outcome']!='blocked' for r in candidate_results)
                broke_users=any(r['id'] in prior_served and r['outcome']!='served' for r in candidate_results)
                unchanged=candidate['version']==self.policy['version']
                accepted=(candidate_score['errors']==0 and candidate_score['invalid']==0 and not unchanged and
                          not regressed and not broke_users and candidate_score['served']>=previous['served'] and
                          candidate_score['blocked']>=previous['blocked'])
                verdict=('accepted' if accepted else 'no policy change' if unchanged else 'infrastructure errors' if candidate_score['errors']
                         else 'reopened a blocked attack' if regressed else 'broke an authorized task' if broke_users or candidate_score['served']<previous['served']
                         else 'fewer attacks blocked')
                self.emit('candidate_verified',round=round_no,accepted=accepted,score=candidate_score,regression=regressed,verdict=verdict)
                old=self.policy
                if accepted:
                    save_version(candidate,self.directory/'defenses');self.policy=candidate;history=candidate_results
                    diffs={f:'\n'.join(difflib.unified_diff(old['files'][f].splitlines(),candidate['files'][f].splitlines(),fromfile=f,tofile=f,lineterm='')) for f in candidate['files']}
                    self.emit('patch_activated',round=round_no,version=candidate['version'],files=candidate['files'],diffs=diffs)
                    final_score=candidate_score;final_results=candidate_results
                else:
                    final_score=previous;final_results=history
                self._record_round(round_no,final_score,final_results,verify_seconds,families,str(plan.get('reason','')),self.policy,
                                   accepted=accepted,lessons=lessons,attack_team_seconds=attack_team_seconds,attempted_score=candidate_score,verdict=verdict,reasons=reasons)
            self.cancelled()
            # Holdout is constructed only now and never passed to any agent.
            held=scenarios('holdout',self.seeds)
            before,_=self.evaluate(held,baseline,'holdout_baseline')
            after,_=self.evaluate(held,self.policy,'holdout_final')
            self.holdout={'baseline':score(before),'final':score(after),'results':after}
            self.emit('holdout_scored',holdout=self.holdout)
            self.status='completed';self.emit('run_completed',state=self.snapshot())
        except InterruptedError:
            self.status='stopped';self.emit('run_stopped')
        except Exception as exc:
            self.error=public_error(exc)+': '+str(exc)[:160] if isinstance(exc,(RuntimeError,ValueError)) else public_error(exc)
            self.status='failed';self.emit('run_failed',error=self.error)

    def _record_round(self,index,stats,results,seconds,families,reason,compiled,**extras):
        item={'round':index,'score':stats,'results':results,'seconds':seconds,'families':families,'reason':reason,'version':compiled['version'],'policy':copy.deepcopy(compiled['policy']),'files':dict(compiled['files']),**extras}
        with self.lock:self.rounds.append(item)
        save_version(compiled,self.directory/'defenses')
        self.emit('round_scored',round=item)
