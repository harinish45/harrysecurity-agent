"""White-label, reproducible report context and theme contracts."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class ReportBranding:
    organization_name: str = "NEXUS-STRIKE"
    logo_path: str = ""
    primary_color: str = "#111827"
    accent_color: str = "#2563eb"
    footer_text: str = "Confidential Security Assessment"
    contact_email: str = ""


@dataclass(frozen=True)
class ReportEngagement:
    client: str = ""
    engagement_id: str = ""
    authorization_reference: str = ""
    assessment_type: str = "Security Assessment"
    scope: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    rules_of_engagement: str = ""


@dataclass(frozen=True)
class ReportProvenance:
    mission_id: str
    platform_version: str = ""
    policy_version: str = "1"
    template_version: str = "1"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tool_versions: tuple[str, ...] = ()
    agent_versions: tuple[str, ...] = ()
    model_identity: str = ""


@dataclass(frozen=True)
class ReportContext:
    branding: ReportBranding = field(default_factory=ReportBranding)
    engagement: ReportEngagement = field(default_factory=ReportEngagement)
    provenance: ReportProvenance = field(default_factory=lambda: ReportProvenance("assessment"))

    def to_dict(self) -> dict[str, object]:
        return {
            "branding": self.branding.__dict__,
            "engagement": self.engagement.__dict__,
            "provenance": self.provenance.__dict__,
        }
