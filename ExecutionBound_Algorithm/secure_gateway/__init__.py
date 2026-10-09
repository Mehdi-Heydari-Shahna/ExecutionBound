"""Model-independent mission authorization and execution gateway."""
from .model_adapter import ModelAdapter, ModelGateway
from .parser import parse_candidate
from .policy import (
    AABB,
    Action,
    Capability,
    Decision,
    DispatchOutcomeUnknown,
    ExecutorSink,
    Gateway,
    Issuer,
    Lease,
    MissionContract,
    Mode,
    PolicyError,
    Provenance,
    canonical_json,
    digest,
    labelled_action,
)

__all__ = [
    "AABB", "Action", "Capability", "Decision", "DispatchOutcomeUnknown",
    "ExecutorSink", "Gateway", "Issuer", "Lease", "MissionContract",
    "Mode", "PolicyError", "Provenance", "canonical_json", "digest",
    "labelled_action", "ModelAdapter", "ModelGateway", "parse_candidate",
]
