import unittest
import lab

class LabTests(unittest.TestCase):
    def test_policy_contracts(self):
        result = lab.evaluate(); self.assertEqual(result['passed'], result['total'])
    def test_sequence_has_traceable_evidence(self):
        result = lab.assess(lab.fixture()); self.assertEqual(result['decision'], 'escalate'); self.assertEqual(len(result['evidence_ids']), 6); self.assertTrue(result['conflicting_intelligence']); self.assertFalse(result['intelligence'][2]['fresh'])
    def test_intelligence_alone_does_not_escalate(self):
        data = lab.fixture(); data['events'] = []; self.assertEqual(lab.assess(data)['decision'], 'insufficient_evidence')
    def test_unrelated_user_does_not_complete_sequence(self):
        data = lab.fixture(); data['events'][-1]['user'] = 'someone-else'; self.assertEqual(lab.assess(data)['decision'], 'insufficient_evidence')
    def test_old_failures_do_not_complete_sequence(self):
        data = lab.fixture(); data['events'][-1]['timestamp'] = '2026-09-19T12:30:00+00:00'; self.assertEqual(lab.assess(data)['decision'], 'insufficient_evidence')
    def test_poisoned_report_does_not_change_verdict(self):
        import json
        data=lab.fixture(); before=lab.assess(data)['decision']; data['intelligence'].append(json.loads((lab.ROOT/'data/poisoned_report.json').read_text())); result=lab.investigate(data); self.assertEqual(result['assessment']['decision'],before); self.assertEqual(len(result['content_detections']),1); self.assertEqual(lab.screen_reports(lab.fixture()),[])
    def test_event_tool_filters_other_users(self):
        data=lab.fixture(); data['events'].append({'user':'executive','id':'PRIVATE'}); result=lab.Boundary(data).call({'tool':'get_auth_events','args':{'user':'analyst-demo'}}); self.assertNotIn('PRIVATE',[event['id'] for event in result])
    def test_malformed_tool_is_denied(self):
        boundary=lab.Boundary(lab.fixture()); self.assertEqual(boundary.call({'tool':[]})['error'],'denied')

if __name__ == '__main__': unittest.main()
