"""Bounded OpenAI Responses adapter. No requests occur on import."""
import argparse
import getpass
import json
import os
import pathlib
import ssl
import re
import urllib.error
import urllib.request
import lab

MODEL = 'gpt-5.4-mini-2026-03-17'


def secure_urlopen(request, timeout=45):
    if os.environ.get('SSL_CERT_FILE') or os.environ.get('SSL_CERT_DIR'):
        context = ssl.create_default_context()
    else:
        try:
            import certifi
        except ImportError:
            context = ssl.create_default_context()
        else:
            context = ssl.create_default_context(cafile=certifi.where())
    return urllib.request.urlopen(request, timeout=timeout, context=context)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


class OpenAIProposer:
    def __init__(self, api_key, max_requests=6, opener=None):
        if not api_key:
            raise ValueError('Set OPENAI_API_KEY or use --prompt-key; never put a key in a report.')
        if not 1 <= max_requests <= 108:
            raise ValueError('max_requests must be between 1 and 108')
        self._api_key = api_key
        self.max_requests = max_requests
        self.opener = opener or secure_urlopen
        self.calls = []
        self.attempts = 0

    def __call__(self, instructions, transcript):
        if self.attempts >= self.max_requests:
            raise RuntimeError('Request limit reached; no further API calls sent.')
        body = {'model': MODEL, 'instructions': instructions,
                'input': 'Return the next tool proposal as JSON.\n' + json.dumps({'transcript': transcript}),
                'text': {'format': {'type': 'json_object'}},
                'reasoning': {'effort': 'none'}, 'max_output_tokens': 512, 'store': False}
        encoded = json.dumps(body).encode('utf-8')
        if len(encoded) > 32000:
            raise RuntimeError('Input size limit reached; no API call sent.')
        request = urllib.request.Request('https://api.openai.com/v1/responses', data=encoded,
                    headers={'Authorization': 'Bearer ' + self._api_key, 'Content-Type': 'application/json'}, method='POST')
        self.attempts += 1
        try:
            with self.opener(request, timeout=45) as response:
                data = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = 'No readable API error details.'
            try:
                payload = json.loads(exc.read(16384))
                error = payload.get('error', {}) if isinstance(payload, dict) else {}
                if isinstance(error, dict):
                    fields = {k: error[k] for k in ('message', 'type', 'code', 'param')
                              if isinstance(error.get(k), (str, int))}
                    if fields:
                        detail = json.dumps(fields)
            except (OSError, ValueError, AttributeError, KeyError):
                pass
            detail = detail.replace(self._api_key, '[REDACTED]')
            detail = re.sub(r'sk-[A-Za-z0-9_-]+', '[REDACTED]', detail)
            raise RuntimeError(f'API HTTP {exc.code}: {detail[:2000]} No automatic retry.') from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                message = 'HTTPS certificate verification failed. Install certifi with: python3 -m pip install --user certifi'
            else:
                message = 'Network connection failed. Check internet access, DNS, proxy, or VPN settings.'
            raise RuntimeError(message + ' No automatic retry.') from None
        except (OSError, ValueError):
            raise RuntimeError('API transport or response error; no retry. Usage for this attempt may be unknown.') from None
        if not isinstance(data, dict):
            raise RuntimeError('Malformed API response.')
        usage = data.get('usage') or {}
        self.calls.append({'response_id': data.get('id'), 'model': data.get('model'),
                           'status': data.get('status'), 'usage': usage})
        if data.get('status') != 'completed':
            raise RuntimeError('API response incomplete; inspect usage in the saved report.')
        parts = []
        refused = False
        for item_index, item in enumerate(data.get('output', [])):
            if item.get('type') != 'message':
                continue
            for part_index, part in enumerate(item.get('content', [])):
                if part.get('type') == 'refusal':
                    refused = True
                if part.get('type') == 'output_text':
                    text = part.get('text', '')
                    if not isinstance(text, str):
                        raise RuntimeError('API returned a non-text output part.')
                    parts.append((item_index, part_index, text))
        self.calls[-1]['output_parts'] = [
            {'item_index': i, 'part_index': p, 'text': self.redact(t)[:2000],
             'truncated': len(self.redact(t)) > 2000} for i, p, t in parts]
        if refused or not parts:
            raise RuntimeError('API returned no usable action or a refusal.')
        distinct = {text for _, _, text in parts}
        if len(distinct) != 1:
            raise RuntimeError('Ambiguous API response: multiple text parts with different content; no action executed. See output_parts.')
        self.calls[-1]['identical_duplicate_parts'] = len(parts) - 1
        output = parts[0][2]
        try:
            action = json.loads(output, object_pairs_hook=unique_object)
        except (json.JSONDecodeError, ValueError):
            raise RuntimeError('Invalid action JSON (possibly duplicate objects or keys); no action executed. See output_parts.') from None
        if (not isinstance(action, dict) or set(action) != {'tool', 'args'}
                or not isinstance(action['tool'], str) or not isinstance(action['args'], dict)):
            raise RuntimeError('Invalid action shape: expected exactly tool (string) and args (object); no action executed.')
        return action

    def redact(self, text):
        return re.sub(r'sk-[A-Za-z0-9_-]+', '[REDACTED]', text.replace(self._api_key, '[REDACTED]'))

    def summary(self):
        input_tokens = sum(c['usage'].get('input_tokens', 0) for c in self.calls)
        output_tokens = sum(c['usage'].get('output_tokens', 0) for c in self.calls)
        unknown = self.attempts - sum('input_tokens' in c['usage'] and 'output_tokens' in c['usage'] for c in self.calls)
        return {'model': MODEL, 'attempted_requests': self.attempts, 'max_requests': self.max_requests,
                'input_tokens': input_tokens, 'output_tokens': output_tokens,
                'attempts_with_unknown_usage': unknown,
                'estimated_known_usage_usd': round((input_tokens * .75 + output_tokens * 4.5) / 1_000_000, 6),
                'pricing_basis': '2026-09-19 standard rates; no cache discount; estimate is not an invoice or dollar cap.',
                'calls': self.calls}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--poisoned', action='store_true')
    parser.add_argument('--prompt-key', action='store_true', help='Read API key with hidden terminal input')
    parser.add_argument('--output', type=pathlib.Path, default=lab.ROOT / 'reports/hosted-investigation.json')
    args = parser.parse_args()
    key = getpass.getpass('OpenAI API key (hidden): ') if args.prompt_key else os.environ.get('OPENAI_API_KEY')
    try:
        proposer = OpenAIProposer(key)
    except ValueError as exc:
        parser.exit(1, str(exc) + '\n')
    data = lab.fixture()
    if args.poisoned:
        data['intelligence'].append(json.loads((lab.ROOT / 'data/poisoned_report.json').read_text()))
    result = lab.investigate(data, proposer=proposer)
    result.update(mode='hosted_model', model=MODEL, provider_usage=proposer.summary())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'completed': result['completed'], 'error': result['error'],
                      'usage': proposer.summary(), 'report': str(args.output)}, indent=2))
    if not result['completed']:
        parser.exit(1, 'Investigation incomplete; see saved report.\n')


if __name__ == '__main__':
    main()
