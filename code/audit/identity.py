"""Identity resolution module with temporal alias tracking and identifier reuse guards.

Resolves identities using stable user_id, current identity snapshots, and historical
changes in user_audit_log.csv without incorrectly merging separate subjects.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import hashlib
import pandas as pd

from code.config import USER_IDENTITIES_PATH, USER_AUDIT_LOG_PATH


@dataclass
class HistoricalChange:
    """Historical modification to a user's identity field."""
    audit_id: str
    user_id: str
    event_time: str
    field_name: str
    old_value: str
    new_value: str


@dataclass
class UserIdentity:
    """Complete subject profile encompassing current and historical identifiers."""
    user_id: str
    name: str
    current_email: str
    current_phone: str
    email_hash: str
    snapshot_updated_at: str
    historical_emails: List[Tuple[str, str, str]] = field(default_factory=list)  # (email, valid_until, audit_id)
    historical_phones: List[Tuple[str, str, str]] = field(default_factory=list)  # (phone, valid_until, audit_id)
    historical_names: List[Tuple[str, str, str]] = field(default_factory=list)

    @property
    def all_emails(self) -> Set[str]:
        emails = {self.current_email.strip().lower()}
        for h_email, _, _ in self.historical_emails:
            if h_email:
                emails.add(h_email.strip().lower())
        return emails

    @property
    def all_phones(self) -> Set[str]:
        phones = {self.current_phone.strip()}
        for h_phone, _, _ in self.historical_phones:
            if h_phone:
                phones.add(h_phone.strip())
        return phones

    @property
    def all_hashes(self) -> Set[str]:
        hashes = set()
        if self.email_hash:
            hashes.add(self.email_hash.strip().lower())
        for em in self.all_emails:
            if em:
                h = hashlib.sha256(em.encode("utf-8")).hexdigest().lower()
                hashes.add(h)
        return hashes


class IdentityResolver:
    """Time-aware identity graph indexing snapshots and audit logs."""

    def __init__(
        self,
        identities_path: Path = USER_IDENTITIES_PATH,
        audit_log_path: Path = USER_AUDIT_LOG_PATH,
    ):
        self.identities_path = identities_path
        self.audit_log_path = audit_log_path
        self.users_by_id: Dict[str, UserIdentity] = {}
        # Email -> list of (user_id, valid_from, valid_until)
        self.email_timeline: Dict[str, List[Tuple[str, Optional[str], Optional[str]]]] = {}
        self.phone_timeline: Dict[str, List[Tuple[str, Optional[str], Optional[str]]]] = {}
        self._load_and_index()

    def _normalize_email(self, email: str) -> str:
        return email.strip().lower() if email else ""

    def _normalize_phone(self, phone: str) -> str:
        return phone.strip() if phone else ""

    def _load_and_index(self) -> None:
        """Read and construct identity index from disk."""
        if not self.identities_path.exists():
            raise FileNotFoundError(f"Missing user_identities.csv at {self.identities_path}")

        identities_df = pd.read_csv(self.identities_path)
        for _, row in identities_df.iterrows():
            uid = str(row["user_id"]).strip()
            c_email = self._normalize_email(str(row["email"]))
            c_phone = self._normalize_phone(str(row.get("phone", "")))
            c_name = str(row.get("name", "")).strip()
            e_hash = str(row.get("email_hash", "")).strip().lower()
            u_at = str(row.get("updated_at", "")).strip()

            user = UserIdentity(
                user_id=uid,
                name=c_name,
                current_email=c_email,
                current_phone=c_phone,
                email_hash=e_hash,
                snapshot_updated_at=u_at,
            )
            self.users_by_id[uid] = user

        # Process audit log for historical transitions
        if self.audit_log_path.exists():
            audit_df = pd.read_csv(self.audit_log_path)
            # Sort chronologically
            audit_df = audit_df.sort_values(by="event_time")
            for _, row in audit_df.iterrows():
                uid = str(row["user_id"]).strip()
                if uid not in self.users_by_id:
                    continue

                field_name = str(row.get("field_name", "")).strip().lower()
                old_val = str(row.get("old_value", "")).strip()
                new_val = str(row.get("new_value", "")).strip()
                event_time = str(row.get("event_time", "")).strip()
                audit_id = str(row.get("audit_id", "")).strip()

                user = self.users_by_id[uid]
                if field_name == "email":
                    norm_old = self._normalize_email(old_val)
                    if norm_old:
                        user.historical_emails.append((norm_old, event_time, audit_id))
                elif field_name == "phone":
                    norm_old = self._normalize_phone(old_val)
                    if norm_old:
                        user.historical_phones.append((norm_old, event_time, audit_id))
                elif field_name == "name":
                    if old_val:
                        user.historical_names.append((old_val, event_time, audit_id))

        # Build reverse lookup timelines
        for uid, user in self.users_by_id.items():
            # Current email valid from snapshot_updated_at or earliest to infinity
            c_email = user.current_email
            if c_email:
                if c_email not in self.email_timeline:
                    self.email_timeline[c_email] = []
                self.email_timeline[c_email].append((uid, user.snapshot_updated_at, None))

            # Historical emails
            for h_email, valid_until, _ in user.historical_emails:
                if h_email:
                    if h_email not in self.email_timeline:
                        self.email_timeline[h_email] = []
                    self.email_timeline[h_email].append((uid, None, valid_until))

    def resolve_by_user_id(self, user_id: str) -> Optional[UserIdentity]:
        """Direct lookup by stable user_id."""
        return self.users_by_id.get(user_id.strip())

    def resolve_by_email(
        self, email: str, as_of_time: Optional[str] = None
    ) -> Optional[UserIdentity]:
        """Resolve a user by current or historical email, respecting temporal validity."""
        norm_email = self._normalize_email(email)
        if not norm_email:
            return None

        candidates = self.email_timeline.get(norm_email, [])
        if not candidates:
            # Check direct fallback on users_by_id
            for u in self.users_by_id.values():
                if norm_email in u.all_emails:
                    return u
            return None

        # If exactly one unique user associated
        unique_uids = {uid for uid, _, _ in candidates}
        if len(unique_uids) == 1:
            return self.users_by_id[list(unique_uids)[0]]

        # Identifier reuse scenario: multiple distinct users have used this email!
        # Differentiate based on as_of_time
        if as_of_time is not None:
            for uid, valid_from, valid_until in candidates:
                # If email was valid until a certain time, and request was before that time
                if valid_until and as_of_time <= valid_until:
                    return self.users_by_id[uid]
                # If email became valid from a certain time, and request was after that time
                if valid_from and as_of_time >= valid_from:
                    return self.users_by_id[uid]

        # If ambiguous and cannot determine temporal owner without guessing,
        # return None to prevent unsafe false merge
        return None

    def get_all_identifiers_for_user(self, user_id: str) -> Dict[str, Set[str]]:
        """Return full identifier dictionary for matching across evidence."""
        user = self.resolve_by_user_id(user_id)
        if not user:
            return {"user_ids": set(), "emails": set(), "phones": set(), "hashes": set()}
        return {
            "user_ids": {user.user_id},
            "emails": user.all_emails,
            "phones": user.all_phones,
            "hashes": user.all_hashes,
            "email_hashes": user.all_hashes,
        }
