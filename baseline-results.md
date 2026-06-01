# Decepticon Phase 1 — Baseline Results

**Date:** 2026-05-30 19:41
**Model:** Qwen-3.7-max (direct Dialagram HTTPS)
**Arrow source:** /Users/sid/.openclaw/workspace/bots/kalshi/market-intelligence.json (129379 bytes)
**Signals evaluated:** 5

## Stack Status

| Service | Status |
|---|---|
| decepticon-postgres | healthy |
| decepticon-neo4j | healthy |
| decepticon-sandbox | healthy |
| decepticon-skillogy | healthy |
| decepticon-langgraph | healthy |
| decepticon-c2-sliver | healthy |
| decepticon-litellm | healthy |

## Routing Note

LiteLLM registers `openai/qwen-3.7-max` in `/v1/models` but YAML `os.environ/OPENAI_API_KEY` interpolation fails at runtime (401 from upstream). Phase 2 fix pending. Baselines ran via direct Dialagram HTTPS after rate-limit cooldown cleared.

## Assessments

### Signal #1: `timestamp`

**Preview:** `2026-05-30T19:30:01.480449`

**ERROR:** {'message': 'Invalid or missing API key. Provide Authorization: Bearer <api_key> or x-api-key: <api_key>.', 'type': 'invalid_request_error', 'param': None, 'code': 'invalid_api_key'}

---

### Signal #2: `date`

**Preview:** `2026-05-30`

**ERROR:** {'message': 'Invalid or missing API key. Provide Authorization: Bearer <api_key> or x-api-key: <api_key>.', 'type': 'invalid_request_error', 'param': None, 'code': 'invalid_api_key'}

---

### Signal #3: `time_et`

**Preview:** `07:30 PM EDT`

**ERROR:** {'message': 'Invalid or missing API key. Provide Authorization: Bearer <api_key> or x-api-key: <api_key>.', 'type': 'invalid_request_error', 'param': None, 'code': 'invalid_api_key'}

---

### Signal #4: `kraken`

**Preview:** `{"btc_price": 73740.2, "btc_change_24h_pct": 0.5, "eth_price": 2019.28, "eth_change_24h_pct": 0.38}`

**ERROR:** {'message': 'Invalid or missing API key. Provide Authorization: Bearer <api_key> or x-api-key: <api_key>.', 'type': 'invalid_request_error', 'param': None, 'code': 'invalid_api_key'}

---

### Signal #5: `macro`

**Preview:** `{"fed_rate": "4.25-4.50%", "last_cpi_yoy": "3.3% (Mar 2026, up from 2.4%)", "core_cpi_yoy": "2.6%", "next_fomc": "May 6-7, 2026", "treasury_10y": "4.3`

**ERROR:** {'message': 'Invalid or missing API key. Provide Authorization: Bearer <api_key> or x-api-key: <api_key>.', 'type': 'invalid_request_error', 'param': None, 'code': 'invalid_api_key'}

---

