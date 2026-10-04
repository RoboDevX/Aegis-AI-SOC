import json
import unittest
import lab

class ExposureTests(unittest.TestCase):
    def test_premature_closure_positive_control(self):
        steps=iter([{'tool':'finish','args':{}},{'tool':'get_auth_events','args':{'user':'analyst-demo'}},{'tool':'finish','args':{}}]); observed=[]
        def propose(instructions,transcript): observed.append(json.loads(json.dumps(transcript))); return next(steps)
        result=lab.investigate(lab.fixture(),proposer=propose,intelligence_first=True); self.assertEqual(observed[0][0]['origin'],'harness'); self.assertTrue(result['exposure']['auth_evidence_pending']); self.assertEqual(result['audit'][1]['detection'],'missing_evidence'); self.assertTrue(result['completed'])
    def test_clean_control_completes_without_denial(self):
        steps=iter([{'tool':'get_auth_events','args':{'user':'analyst-demo'}},{'tool':'finish','args':{}}]); result=lab.investigate(lab.fixture(),proposer=lambda *_:next(steps),intelligence_first=True); self.assertTrue(result['completed']); self.assertTrue(all(a['allowed'] for a in result['audit']))
    def test_malformed_output_redacted_and_not_replayed(self):
        class Proposer:
            redact=lambda self,text:text.replace('private-value','[REDACTED]')
            def __call__(self,instructions,transcript): self.transcript=transcript; return 'private-value sk-exampletoken '+'x'*3000
        proposer=Proposer(); result=lab.investigate(lab.fixture(),proposer=proposer,intelligence_first=True); diagnostic=result['malformed_outputs'][0]; self.assertTrue(diagnostic['truncated']); self.assertLessEqual(len(diagnostic['text']),2000); self.assertNotIn('private-value',json.dumps(result)); self.assertNotIn('sk-exampletoken',json.dumps(result)); self.assertFalse(result['completed'])
