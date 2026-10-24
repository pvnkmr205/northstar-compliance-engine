# Deletion Audit Schema Digest

## 1. Tables & Primary/Foreign Key Relationships
- **deletion_requests** (PK: `case_id`): `email` (FK -> `user_identities.email`), `requested_at`, `reported_status`, `reported_at`, `audit_at`, `request_text`
- **user_identities** (PK: `user_id`): `name`, `email` (UQ), `phone`, `email_hash`, `updated_at`
- **user_audit_log** (PK: `audit_id`): `user_id` (FK -> `user_identities.user_id`), `event_time`, `field_name`, `old_value`, `new_value`
- **system_activity** (PK: `activity_id`): `event_time`, `event_type`, `source_system`, `target_system`, `resource_id` (links to service resources), `reported_result`, `details`
- **deletion_rules** (PK: `rule_id`): `data_category`, `condition`, `required_action`

## 2. Unique ENUM Values
- **deletion_requests.reported_status**: `COMPLETE`, `PARTIALLY_COMPLETE`, `NOT_STARTED`
- **system_activity activity types**: `ANONYMIZE_RECORD`, `BLOCK_RESTORE`, `CHECK_DATA_FLOW`, `CHECK_RESTORE_ACCESS`, `CLASSIFY_REQUEST`, `CREATE_EXPORT`, `DELETE_RECORD`, `DISABLE_DATA_FLOW`, `INDEX_RECORD`, `LINK_RESOURCE_IDENTITY`, `REDACT_RECORD`, `REFRESH_CACHE`, `RESTORE_BACKUP`, `RETAIN_RECORD`, `SEND_EMAIL`, `SYNC_RECORD`, `UPDATE_RECORD`
- **deletion_rules treatments**: `ANONYMIZE`, `DELETE`, `REDACT`, `RETAIN`

## 3. Canonical Input-to-Output Trace Mappings

### COMPLETE Trace (`case_01`)
- **Input**: `case_id`: `case_01`
- **Output**: `deletion_status`: `COMPLETE`
- **Steps**:
  - `step_no`: 1 | `phase`: `VERIFICATION` | `system_id`: `account_service` | `resource_id`: `account_001` | `operation`: `VERIFY_RECORD_ABSENT` | `state`: `ABSENT` | `evidence_id`: `evidence_54`

### INCOMPLETE Trace (`case_05`)
- **Input**: `case_id`: `case_05`
- **Output**: `deletion_status`: `INCOMPLETE`
- **Steps (FINDING -> REMEDIATION -> VERIFICATION)**:
  - `step_no`: 1 | `phase`: `FINDING` | `system_id`: `account_service` | `resource_id`: `account_005` | `operation`: `REPORT_REMAINING_RECORD` | `state`: `PRESENT` | `evidence_id`: `evidence_54`
  - `step_no`: 2 | `phase`: `REMEDIATION` | `system_id`: `account_service` | `resource_id`: `account_005` | `operation`: `DELETE_RECORD` | `state`: `ABSENT` | `evidence_id`: `""`
  - `step_no`: 3 | `phase`: `VERIFICATION` | `system_id`: `account_service` | `resource_id`: `account_005` | `operation`: `VERIFY_RECORD_ABSENT` | `state`: `ABSENT` | `evidence_id`: `""`
