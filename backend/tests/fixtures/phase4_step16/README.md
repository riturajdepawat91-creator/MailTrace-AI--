# Phase 4 Step 16 synthetic email corpus

This is a small, offline evaluation corpus for parser and analysis regression work. Every `.eml` file was authored for this repository; none was collected from a mailbox, downloaded from a threat feed, or copied from an existing sample. All addresses and hostnames use the reserved `.invalid` namespace, and any IP literal uses an RFC 5737 documentation range. There are no real people, live credentials, active links, or attachments.

## Use and safety

- Read samples as inert RFC 5322/MIME text. Do not open them in a mail client or visit any URL-like string.
- For tests, parse locally and stub/disable network-backed validators, enrichment, and reputation lookups. These labels are fixture expectations, not reputation-feed assertions.
- This corpus does not require external services. Do not submit it to external providers.
- The samples exercise structure and policy distinctions; they are not a balanced training set and do not establish model accuracy.

## Naming and labels

Stable IDs are `MT-F16-NNNN`; filenames use the same ID. Labels and rationale live in `manifest.json`, separate from the message evidence. The fixture author completed a content/safety QA review and each entry records `qa_review_status: "PASS"`; independent human review was not performed and is recorded as `human_review_status: "not_performed"`. A maintainer should review the manifest before treating it as a benchmark or training data.

The current corpus uses the existing `backend/tests/` pytest tree and keeps data fixtures in a dedicated `fixtures/phase4_step16/` directory. Existing sample files elsewhere in the repository remain untouched because their provenance, safety, or label quality is not sufficient for this corpus.

Run the offline corpus checks from `backend/` with `python -m pytest -q tests/test_phase4_step16_fixture_corpus.py`.
