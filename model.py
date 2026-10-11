"""One shared Luminal connection, bounded parallel calls, explicit failures."""
import asyncio
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

_env = Path(__file__).parent / '.env'
for line in _env.read_text(encoding='utf-8').splitlines() if _env.exists() else []:
    if '=' in line and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

@dataclass
class ModelConfig:
    base_url: str = os.environ.get('LLM_BASE_URL', 'https://flash.luminal.cloud/v1')
    api_key: str = os.environ.get('LUMINAL_API_KEY', os.environ.get('LLM_API_KEY', ''))
    model: str = os.environ.get('LLM_MODEL', 'deepseek-ai/DeepSeek-V4.1-Flash')

CONFIG = ModelConfig()
_client = None
_lock = threading.Lock()
_capacity = threading.BoundedSemaphore(6)

def _get_client():
    global _client
    with _lock:
        if _client is None:
            from openai import OpenAI
            if not CONFIG.api_key:
                raise RuntimeError('LUMINAL_API_KEY is missing')
            _client = OpenAI(base_url=CONFIG.base_url, api_key=CONFIG.api_key, timeout=45, max_retries=1)
    return _client

def call_model(system, user, temperature=0.5, max_tokens=1800, json_output=False):
    with _capacity:
        response = _get_client().chat.completions.create(model=CONFIG.model,
            messages=[{'role':'system','content':system}, {'role':'user','content':user}],
            temperature=temperature, max_tokens=max_tokens,
            extra_body={'thinking': {'type': 'disabled'}},
            **({'response_format': {'type':'json_object'}} if json_output else {}))
    result = response.choices[0]
    if result.finish_reason == 'length':
        raise RuntimeError('Model output exceeded its token budget')
    if not result.message.content:
        raise RuntimeError('Model returned an empty response')
    return result.message.content

async def call_model_async(system, user, temperature=0.5, max_tokens=1800):
    return await asyncio.to_thread(call_model, system, user, temperature, max_tokens)

def json_model(system, data, max_tokens=1800):
    raw = call_model(system + '\nReturn one valid JSON object, without Markdown.',
                     json.dumps(data, ensure_ascii=False), max_tokens=max_tokens, json_output=True)
    text = re.sub(r'^```(?:json)?\s*|\s*```$', '', raw.strip())
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object from the agent')
    return value

def public_error(exc):
    status = getattr(exc, 'status_code', None)
    return type(exc).__name__ + (f' (HTTP {status})' if status else '')
