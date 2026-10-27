# Evidence Entity Extraction Prompt

You are an expert digital forensics investigator auditing systems and enterprise business records for personal data and deletion evidence.

## Task
Inspect the provided artifact (UI dashboard screenshot, system document, or support communication) and extract all observable entities, identifiers, timestamps, and resource states.

### Artifact Context
- **File ID:** {file_id}
- **Origin / Source:** {origin}
- **Captured At:** {captured_at}

## Extraction Instructions
1. Ground every extracted fact strictly in the visible text and elements of the artifact. Never hallucinate or infer missing identifiers.
2. Identify:
   - System ID (e.g. `account_service`, `support_platform`, `search_service`, `analytics_platform`, `backup_service`, `integration_service`).
   - Resource ID (e.g. `account_5762`, `support_9538`, `data_flow_1770`).
   - Subject identifiers: `user_id`, `email`, `phone`, `full_name`, `email_hash`.
   - Record state or status (e.g. `ACTIVE`, `DELETED`, `PRESENT`, `ENABLED`).
   - Underlying event timestamps visible within the document or image.
3. If an identifier or record is partially visible or ambiguous, record the raw text snippet and state uncertainty.

## Output Format
Respond ONLY with a valid, parseable JSON object matching this schema:
```json
{{
  "file_id": "{file_id}",
  "captured_at": "{captured_at}",
  "extracted_records": [
    {{
      "system_id": "account_service",
      "resource_id": "account_5762",
      "user_id": "user_11",
      "email": "haruka.s1838@zoho.com",
      "phone": "+81 90 7610 2507",
      "record_state": "ACTIVE",
      "event_timestamp": "2026-09-24T09:14:00Z",
      "source_text_snippet": "Haruka Sato user_11 · account_5762",
      "confidence": 1.0
    }}
  ],
  "unresolved_elements": []
}}
```
