"""Offline detection evaluation against author-labeled synthetic scenarios."""
import hashlib
import json
import lab


def evaluate():
    raw = (lab.ROOT / 'data/login_cases.json').read_bytes()
    cases = json.loads(raw)
    counts = dict(TP=0, FP=0, TN=0, FN=0)
    results = []
    for case in cases:
        assessment = lab.assess(case['data'])
        predicted = assessment['decision'] == 'escalate'
        category = ('T' if predicted == case['malicious'] else 'F') + ('P' if predicted else 'N')
        counts[category] += 1
        results.append({'case': case['id'], 'ground_truth_malicious': case['malicious'],
                        'label_rationale': case['label_rationale'], 'classification': category,
                        'assessment': assessment})
    tp, fp, tn, fn = (counts[k] for k in ('TP', 'FP', 'TN', 'FN'))
    return {'mode': 'offline_rule_evaluation', 'rule': 'AUTH-001: five unique failures then success within 600 seconds',
            'corpus_sha256': hashlib.sha256(raw).hexdigest(), 'corpus_split': 'synthetic development',
            'counts': counts, 'precision': tp/(tp+fp) if tp+fp else None,
            'recall': tp/(tp+fn) if tp+fn else None, 'cases': results,
            'limitations': ['Author-defined ground truth; not independently validated or held out.',
                           'An escalation is a review recommendation, not a finding of compromise.',
                           'Identical observations can describe benign and malicious behavior; labels are not passed to the rule.',
                           'Metrics describe these chosen cases only, not production accuracy.']}


def main():
    result = evaluate()
    path = lab.ROOT / 'reports/detection-evaluation.json'
    path.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k: result[k] for k in ('counts','precision','recall')},indent=2))
    print('Report:',path)


if __name__ == '__main__':
    main()
