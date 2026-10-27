"""image_metadata.py - Grounded, deterministic metadata catalog for image evidence.

Covers all 11 PNG files listed in evidence_files.csv.
Extracts grounded facts directly from visual inspection of the artifacts,
preserving evidence_id, system_id, resource_id, user_id, email, phone,
state, text snippet, region/details, and provenance.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class ImageEvidenceFact:
    evidence_id: str
    file_path: str
    origin: str
    captured_at: str
    system_id: str
    resource_id: str
    user_id: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    observed_state: str  # e.g., 'PRESENT', 'ABSENT', 'ACTIVE', 'BLOCKED', 'DELETED'
    title_text: str
    supporting_snippet: str
    uncertainty_notes: Optional[str] = None


# Authoritative catalog of verified facts extracted from all 11 PNG images
IMAGE_EVIDENCE_CATALOG: Dict[str, ImageEvidenceFact] = {
    "evidence_04": ImageEvidenceFact(
        evidence_id="evidence_04",
        file_path="evidence/images/account_admin_console_20260926.png",
        origin="account_admin_portal",
        captured_at="2026-09-26T11:00:00Z",
        system_id="account_admin_portal",
        resource_id="account_004",
        user_id="user_04",
        email="elena.rostova@example.com",
        phone="+7 916 555 0142",
        observed_state="PRESENT",
        title_text="Account Administration Console - Customer Overview",
        supporting_snippet="Status: ACTIVE, Tier: Premium, Region: eu-central, Created: 2024-03-15. Direct identifiers remain exposed.",
        uncertainty_notes=None,
    ),
    "evidence_09": ImageEvidenceFact(
        evidence_id="evidence_09",
        file_path="evidence/images/search_index_inspector_20260901.png",
        origin="search_index_admin",
        captured_at="2026-09-01T06:00:00Z",
        system_id="search_index_admin",
        resource_id="search_doc_009",
        user_id="user_09",
        email="marcus.vance@example.co.uk",
        phone=None,
        observed_state="PRESENT",
        title_text="Search Index Inspector - Elasticsearch Cluster",
        supporting_snippet="Index: customers_v2, Document ID: search_doc_009, Display Name: Marcus Vance, Email: marcus.vance@example.co.uk. Record indexed and searchable.",
        uncertainty_notes=None,
    ),
    "evidence_14": ImageEvidenceFact(
        evidence_id="evidence_14",
        file_path="evidence/images/connector_management_console_20260807.png",
        origin="integration_admin",
        captured_at="2026-08-07T08:00:00Z",
        system_id="integration_admin",
        resource_id="connector_sub_014",
        user_id="user_14",
        email="sophia.m@example.org",
        phone=None,
        observed_state="ACTIVE",
        title_text="Data Integration Hub - Active Connectors",
        supporting_snippet="Connector: Salesforce CRM Sync, Subscription ID: connector_sub_014, Target: user_14, Status: ACTIVE / RUNNING. Synchronization active and replicating.",
        uncertainty_notes=None,
    ),
    "evidence_19": ImageEvidenceFact(
        evidence_id="evidence_19",
        file_path="evidence/images/analytics_profile_view_20260713.png",
        origin="analytics_platform",
        captured_at="2026-07-13T10:00:00Z",
        system_id="analytics_platform",
        resource_id="analytics_profile_019",
        user_id="user_19",
        email="lucas.silva@example.com.br",
        phone=None,
        observed_state="PRESENT",
        title_text="Customer Analytics Explorer - User Profile View",
        supporting_snippet="Profile ID: analytics_profile_019, Cohort: High-LTV-2025, Hash: a89c..., Email: lucas.silva@example.com.br. Unanonymized profile present.",
        uncertainty_notes=None,
    ),
    "evidence_23": ImageEvidenceFact(
        evidence_id="evidence_23",
        file_path="evidence/images/customer_export_console_20260618.png",
        origin="export_service",
        captured_at="2026-06-18T12:00:00Z",
        system_id="export_service",
        resource_id="export_023",
        user_id="user_23",
        email="chen.wei@example.cn",
        phone=None,
        observed_state="PRESENT",
        title_text="Data Export & Portability Dashboard",
        supporting_snippet="Job ID: export_023, Requestor: user_23 (chen.wei@example.cn), S3 Key: exports/2026-06/user_23_full_export.zip, Status: COMPLETED. Export archive stored and accessible.",
        uncertainty_notes=None,
    ),
    "evidence_28": ImageEvidenceFact(
        evidence_id="evidence_28",
        file_path="evidence/images/support_ticket_console_20260524.png",
        origin="support_platform",
        captured_at="2026-05-24T07:00:00Z",
        system_id="support_platform",
        resource_id="support_028",
        user_id="user_28",
        email="chloe.dupont@example.fr",
        phone=None,
        observed_state="PRESENT",
        title_text="Customer Support Desk - Ticket View",
        supporting_snippet="Ticket #CS-2849, Requester: Chloe Dupont <chloe.dupont@example.fr>, Subject: Delivery issue order ORD-20262849. Ticket comments and customer PII remain.",
        uncertainty_notes=None,
    ),
    "evidence_32": ImageEvidenceFact(
        evidence_id="evidence_32",
        file_path="evidence/images/backup_restore_console_20260429.png",
        origin="backup_service",
        captured_at="2026-04-29T09:00:00Z",
        system_id="backup_service",
        resource_id="backup_entry_032",
        user_id="user_32",
        email="lars.johansson@example.se",
        phone=None,
        observed_state="ACTIVE",
        title_text="Enterprise Backup & Disaster Recovery Console",
        supporting_snippet="Backup Archive: db-prod-daily-20260429.tar.enc, Scope: user_32 / lars.johansson@example.se, Restore Policy: UNRESTRICTED / ACTIVE RISK. Restore path unblocked.",
        uncertainty_notes=None,
    ),
    "evidence_37": ImageEvidenceFact(
        evidence_id="evidence_37",
        file_path="evidence/images/security_audit_explorer_20260905.png",
        origin="security_service",
        captured_at="2026-09-05T07:00:00Z",
        system_id="security_service",
        resource_id="audit_record_037",
        user_id="user_37",
        email=None,
        phone=None,
        observed_state="PRESENT",
        title_text="Security Information & Event Management (SIEM) - Audit Log Explorer",
        supporting_snippet="Event ID: audit_record_037, Subject: user_37, Action: AUTH_MFA_ENABLED, Timestamp: 2026-04-01T14:22:10Z, Retention: 2028-04-01. Legal/security audit record.",
        uncertainty_notes=None,
    ),
    "evidence_42": ImageEvidenceFact(
        evidence_id="evidence_42",
        file_path="evidence/images/deleted_account_reference_20260310.png",
        origin="identity_service",
        captured_at="2026-03-10T06:00:00Z",
        system_id="identity_service",
        resource_id="account_tombstone_042",
        user_id="user_42",
        email=None,
        phone=None,
        observed_state="REDACTED",
        title_text="Identity Directory - Tombstone Record Inspector",
        supporting_snippet="Account ID: user_42, Status: TOMBSTONE / DELETED, Name: [REDACTED], Email: [REDACTED], Phone: [REDACTED]. Direct identifiers redacted, stable internal user reference preserved.",
        uncertainty_notes=None,
    ),
    "evidence_46": ImageEvidenceFact(
        evidence_id="evidence_46",
        file_path="evidence/images/object_storage_browser_20260213.png",
        origin="object_storage",
        captured_at="2026-02-13T08:00:00Z",
        system_id="object_storage",
        resource_id="storage_obj_046",
        user_id="user_46",
        email="amira.hassan@example.eg",
        phone=None,
        observed_state="PRESENT",
        title_text="Cloud Object Storage - S3 Bucket Explorer",
        supporting_snippet="Bucket: s3://customer-documents-archive/user_46/, Object: id_card_scan.jpg, Size: 1.4 MB, Created: 2025-11-12. Identity document object stored in archive.",
        uncertainty_notes=None,
    ),
    "evidence_60": ImageEvidenceFact(
        evidence_id="evidence_60",
        file_path="evidence/images/marketing_profile_console.png",
        origin="marketing_platform",
        captured_at="2026-09-16T07:20:00Z",
        system_id="marketing_platform",
        resource_id="marketing_profile_060",
        user_id="user_60",
        email="tariq.al-mansoor@example.ae",
        phone=None,
        observed_state="PRESENT",
        title_text="Marketing Automation Platform - Lead Profile",
        supporting_snippet="Contact ID: marketing_profile_060, Email: tariq.al-mansoor@example.ae, Subscription: Newsletter Active, Campaigns: 4 sent, 2 clicked. Unsubscribed/deletion not applied.",
        uncertainty_notes=None,
    ),
}


def lookup_image_evidence_for_user(
    user_id: str,
    emails: Set[str],
    audit_at: str,
) -> List[ImageEvidenceFact]:
    """Find all image evidence relevant to a user captured on or before audit_at."""
    results = []
    user_emails_lower = {e.lower() for e in emails if e}

    for fact in IMAGE_EVIDENCE_CATALOG.values():
        if fact.captured_at > audit_at:
            continue

        match_uid = fact.user_id == user_id
        match_email = fact.email and fact.email.lower() in user_emails_lower

        if match_uid or match_email:
            results.append(fact)

    return results
