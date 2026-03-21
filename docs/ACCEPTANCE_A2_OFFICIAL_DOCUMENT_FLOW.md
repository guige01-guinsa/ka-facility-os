# A2 Acceptance: Official Document to Closure Report

## Purpose

- Fix the owner happy-path for `공문 접수 -> 첨부 저장 -> 기한초과 sync -> 작업지시 -> 공문 리포트`.
- Leave role-matrix expansion for a later acceptance pass.

## Scenario

1. Receive an official document with a due date already exceeded.
2. Upload and verify the original attachment.
3. Run overdue sync and verify a linked work order exists.
4. Close the document with a closure report.
5. Verify the monthly official-document report reflects the document and linked work order.

## Fixed Input

- Site: `A2 Acceptance Site`
- Organization: `한전`
- Document number: `KEPCO-A2-2026-0314`
- Attachment: `official-origin.pdf`

## Pass Criteria

- Official document is created and attachment is stored/downloadable.
- Overdue sync creates or reuses a linked work order for the document.
- Closure report updates the document to `closed`.
- Audit log contains `official_document_create`, `official_document_attachment_upload`, `official_document_overdue_sync`, `official_document_close`.
- Monthly official-document report includes the document with attachment and linked work order counts.

## Execution

```powershell
.\scripts\run_pytest.ps1 -q tests/api/test_acceptance_a2.py
.\scripts\run_pytest.ps1 -q -m acceptance
```
