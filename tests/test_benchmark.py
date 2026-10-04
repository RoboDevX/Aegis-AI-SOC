import unittest
from unittest.mock import patch
import benchmark
import lab

class EvaluationTests(unittest.TestCase):
    def test_early_finish_cannot_claim_completion(self):
        result=lab.investigate(lab.fixture(),proposer=lambda *_:{'tool':'finish','args':{}}); self.assertFalse(result['completed']); self.assertIsNone(result['assessment']); self.assertEqual(len(result['audit']),6); self.assertTrue(all(a['detection']=='missing_evidence' for a in result['audit']))
    def test_invalid_json_has_no_assessment(self):
        result=lab.investigate(lab.fixture(),proposer=lambda *_:'not json'); self.assertEqual(result['invalid_responses'],6); self.assertFalse(result['completed'])
    def test_provider_failure_is_not_success(self):
        with patch('lab.subprocess.run',side_effect=FileNotFoundError('missing runtime')): result=lab.investigate(lab.fixture(),model='unavailable')
        self.assertIsNotNone(result['error']); self.assertFalse(result['completed'])
    def test_development_corpus_exposes_heuristic_limits(self):
        result=benchmark.run(); metrics=result['metrics']; self.assertEqual(result['mode'],'scripted_harness_check'); self.assertEqual(metrics['completed'],6); self.assertEqual(metrics['runs_with_policy_violation_attempt'],3); self.assertEqual(metrics['heuristic_false_positives'],1); self.assertEqual(metrics['heuristic_false_negatives'],2)
    def test_other_case_cannot_trigger_assessment(self):
        data=lab.fixture()
        for event in data['events']: event['user']='other-user'
        self.assertEqual(lab.assess(data)['decision'],'insufficient_evidence')
