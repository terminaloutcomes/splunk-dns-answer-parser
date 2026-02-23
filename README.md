# dns-answer-parser

Splunk search command app providing `dnsparse`, which decodes a base64 DNS wire response and extracts parsed records/values.

## Search usage

```splunk-spl
... | dnsparse field=response_b64
```

Output fields:

- `dnsparse_values`
- `dnsparse_records`
- `dnsparse_query_count`
- `dnsparse_answer_count`
- `dnsparse_authority_count`
- `dnsparse_additional_count`
- `dnsparse_error` (only when parse fails)

## Development

Run checks with `uv run`:

```bash
uv run pytest
uv run ruff check
uv run ty check
```
