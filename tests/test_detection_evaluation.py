import copy
import unittest
import detection_evaluation
import lab

class DetectionTests(unittest.TestCase):
    def test_replayed_event_cannot_create_five_attempts(self):
        data=lab.fixture(); data['events']=[copy.deepcopy(data['events'][0]) for _ in range(5)]+[data['events'][-1]]; self.assertEqual(lab.assess(data)['decision'],'insufficient_evidence')
    def test_conflicting_duplicate_is_not_silently_accepted(self):
        data=lab.fixture(); event=copy.deepcopy(data['events'][0]); event['outcome']='success'; data['events'].append(event)
        with self.assertRaisesRegex(ValueError,'Conflicting'): lab.assess(data)
    def test_evidence_does_not_depend_on_delivery_order(self):
        data=lab.fixture(); expected=lab.assess(data)['evidence_ids']; data['events'].reverse(); self.assertEqual(lab.assess(data)['evidence_ids'],expected)
    def test_exact_window_and_one_second_beyond(self):
        data=lab.fixture(); data['events'][-1]['timestamp']='2026-09-19T12:00:00+00:00'; self.assertEqual(lab.assess(data)['decision'],'escalate'); data['events'][-1]['timestamp']='2026-09-19T12:00:01+00:00'; self.assertEqual(lab.assess(data)['decision'],'insufficient_evidence')
    def test_measurement_keeps_known_failures(self):
        result=detection_evaluation.evaluate(); self.assertEqual(result['counts'],{'TP':3,'FP':1,'TN':6,'FN':2}); self.assertEqual(result['precision'],.75); self.assertEqual(result['recall'],.6)
        for case in result['cases']:
            ids=case['assessment']['evidence_ids']; self.assertEqual(len(ids),len(set(ids)))
