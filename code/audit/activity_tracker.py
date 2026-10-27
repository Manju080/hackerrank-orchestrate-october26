"""Activity tracking module for global system events, data flows, and restore risks.

Tracks synchronization, connector configurations, backup jobs, and restore operations
while strictly enforcing temporal cutoffs and distinguishing event time from capture time.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
import pandas as pd

from code.config import SYSTEM_ACTIVITY_PATH


@dataclass
class ActivityEvent:
    """Normalized activity event from system_activity.csv."""
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass
class FlowAndRiskFact:
    """Normalized finding candidate relating to data flows or restore risks."""
    fact_type: str  # "DATA_FLOW", "RESTORE_RISK", "SYNC_EVENT"
    system_id: str
    resource_id: str
    source_system: str
    target_system: str
    event_time: str
    evidence_id: Optional[str]
    details: str
    is_active_risk: bool


class ActivityTracker:
    """Tracks global operational activity and detects recreation risks."""

    def __init__(self, activity_path: Path = SYSTEM_ACTIVITY_PATH):
        self.activity_path = activity_path
        self.events: List[ActivityEvent] = []
        self._load_activity()

    def _load_activity(self) -> None:
        """Load and chronologically sort global system activity."""
        if not self.activity_path.exists():
            raise FileNotFoundError(f"Missing system_activity.csv at {self.activity_path}")

        df = pd.read_csv(self.activity_path)
        # Ensure chronological ordering
        df = df.sort_values(by="event_time")
        self.activity_df = df
        for _, row in df.iterrows():
            event = ActivityEvent(
                activity_id=str(row["activity_id"]).strip(),
                event_time=str(row["event_time"]).strip(),
                event_type=str(row.get("event_type", "")).strip(),
                source_system=str(row.get("source_system", "")).strip(),
                target_system=str(row.get("target_system", "")).strip(),
                resource_id=str(row.get("resource_id", "")).strip(),
                reported_result=str(row.get("reported_result", "")).strip(),
                details=str(row.get("details", "")).strip(),
            )
            self.events.append(event)

    def get_events_for_resource(
        self, resource_id: str, cutoff_time: Optional[str] = None
    ) -> List[ActivityEvent]:
        """Return all events for a given resource_id up to cutoff_time."""
        matched = []
        for ev in self.events:
            if ev.resource_id == resource_id:
                if cutoff_time is None or ev.event_time <= cutoff_time:
                    matched.append(ev)
        return matched

    def detect_data_flow_risks(
        self,
        associated_resources: Set[str],
        audit_at: str,
    ) -> List[FlowAndRiskFact]:
        """Detect active connectors or sync jobs targeting the user's systems."""
        facts: List[FlowAndRiskFact] = []

        for ev in self.events:
            # Enforce temporal cutoff
            if ev.event_time > audit_at:
                continue

            is_connector = (
                "integration" in ev.source_system.lower()
                or "integration" in ev.target_system.lower()
                or "data_flow" in ev.resource_id.lower()
                or "connector" in ev.resource_id.lower()
                or "data_flow" in ev.details.lower()
            )
            if is_connector and ev.resource_id in associated_resources:
                if ev.event_type in ["SYNC_RECORD", "INDEX_RECORD", "UPDATE_RECORD", "CREATE_CONNECTOR"]:
                    facts.append(
                        FlowAndRiskFact(
                            fact_type="DATA_FLOW",
                            system_id=ev.target_system,
                            resource_id=ev.resource_id,
                            source_system=ev.source_system,
                            target_system=ev.target_system,
                            event_time=ev.event_time,
                            evidence_id=ev.activity_id,
                            details=ev.details,
                            is_active_risk=ev.reported_result in ["SUCCESS", "PARTIAL", "ACTIVE"],
                        )
                    )

        return facts

    def detect_restore_risks(
        self,
        user_resources: Set[str],
        audit_at: str,
    ) -> List[FlowAndRiskFact]:
        """Detect backup and restoration risks present before audit_at."""
        backup_events: Dict[str, ActivityEvent] = {}
        blocked_backups: Set[str] = set()

        for ev in self.events:
            if ev.event_time > audit_at:
                continue

            if "backup" in ev.source_system.lower() or "backup" in ev.target_system.lower() or "backup" in ev.event_type.lower():
                is_related = ev.resource_id in user_resources or any(r in ev.details for r in user_resources)
                if is_related:
                    if ev.event_type == "BLOCK_RESTORE" and ev.reported_result in ["SUCCESS", "COMPLETE"]:
                        blocked_backups.add(ev.resource_id)
                    else:
                        backup_events[ev.resource_id] = ev

        risks: List[FlowAndRiskFact] = []
        for res_id, ev in backup_events.items():
            if res_id not in blocked_backups:
                risks.append(
                    FlowAndRiskFact(
                        fact_type="RESTORE_RISK",
                        system_id=ev.source_system if "backup" in ev.source_system else ev.target_system,
                        resource_id=ev.resource_id,
                        source_system=ev.source_system,
                        target_system=ev.target_system,
                        event_time=ev.event_time,
                        evidence_id=ev.activity_id,
                        details=ev.details,
                        is_active_risk=True,
                    )
                )

        return risks
