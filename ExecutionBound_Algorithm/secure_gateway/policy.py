"""Mission-scoped authorization and execution-bound dispatch.

Physical validation and actuation are supplied through trusted callbacks.
The caller supplies model-specific trajectories and state snapshots.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from hashlib import sha256
import hmac
import json
import math
import secrets
import threading
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence


class PolicyError(ValueError):
    """Malformed schema, noncanonical data, or an invalid authority operation."""


class DispatchOutcomeUnknown(RuntimeError):
    """Publication was attempted; a callback error cannot prove no side effect."""


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PolicyError("nonfinite_number")
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(k, str) for k in value):
            raise PolicyError("nonstring_key")
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    raise PolicyError("unsupported_json_type:" + type(value).__name__)


def canonical_json(value: Any) -> str:
    """Finite JSON only. No pickle, eval, silent string conversion, or NaN."""
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True)


def digest(value: Any) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _text(v: Any, name: str) -> str:
    if not isinstance(v, str) or not v or len(v) > 256:
        raise PolicyError("invalid_" + name)
    return v


def _number(v: Any, name: str, minimum: float | None = None) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise PolicyError("invalid_" + name)
    try:
        if not math.isfinite(v):
            raise PolicyError("invalid_" + name)
        result = float(v)
    except (OverflowError, ValueError) as exc:
        raise PolicyError("invalid_" + name) from exc
    if minimum is not None and v < minimum:
        raise PolicyError("invalid_" + name)
    return result


def _audit_time(value: Any) -> float | None:
    """Malformed request data must never trigger a second audit-path failure."""
    try:
        return _number(value, "audit_time", 0)
    except (PolicyError, OverflowError, TypeError, ValueError):
        return None


def _integer(v: Any, name: str, minimum: int = 0) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        raise PolicyError("invalid_" + name)
    return v


def _xyz(v: Any) -> tuple[float, float, float]:
    if not isinstance(v, (list, tuple)) or len(v) != 3:
        raise PolicyError("invalid_xyz")
    return tuple(_number(x, "xyz") for x in v)


def _names(v: Any, name: str) -> tuple[str, ...]:
    if not isinstance(v, (list, tuple)) or not v:
        raise PolicyError("invalid_" + name)
    names = tuple(_text(x, name) for x in v)
    if len(set(names)) != len(names):
        raise PolicyError("duplicate_" + name)
    return names


class Mode(str, Enum):
    B0 = "B0"
    B1_FILTER_SURROGATE = "B1_FILTER_SURROGATE"
    B2_SEMANTIC = "B2_SEMANTIC"
    B3_PHYSICAL = "B3_PHYSICAL"
    B23_SEMANTIC_PHYSICAL = "B23_SEMANTIC_PHYSICAL"
    B4_FULL = "B4_FULL"
    B4_NO_PROVENANCE = "B4_NO_PROVENANCE"
    B4_NO_SCOPE = "B4_NO_SCOPE"
    B4_NO_FRESHNESS = "B4_NO_FRESHNESS"
    B4_NO_REVOCATION = "B4_NO_REVOCATION"
    B4_NO_BINDING = "B4_NO_BINDING"
    B4_NO_BUDGET = "B4_NO_BUDGET"
    B4_STATIC_PERMISSIONS = "B4_STATIC_PERMISSIONS"
    # Check-then-dispatch comparator: every authorization and physical check is
    # evaluated once at validation; dispatch verifies only the approval token
    # (MAC, expiry, one-time use) and publishes the presented command.
    B4_TIME_OF_CHECK = "B4_TIME_OF_CHECK"
    # Original dispatch-bound design: the live state at dispatch must equal the
    # validated snapshot bit for bit (no certified state tube).
    B4_EXACT_STATE = "B4_EXACT_STATE"


@dataclass(frozen=True)
class AABB:
    lo: tuple[float, float, float]
    hi: tuple[float, float, float]

    def __post_init__(self):
        object.__setattr__(self, "lo", _xyz(self.lo))
        object.__setattr__(self, "hi", _xyz(self.hi))
        if any(a > b for a, b in zip(self.lo, self.hi)):
            raise PolicyError("invalid_aabb")

    def contains(self, point: Sequence[float]) -> bool:
        return all(a <= p <= b for a, p, b in zip(self.lo, _xyz(point), self.hi))

    def to_dict(self):
        return {"lo": self.lo, "hi": self.hi}


@dataclass(frozen=True)
class MissionContract:
    mission_id: str
    version: int
    destinations: Mapping[str, AABB]
    allowed_skills: tuple[str, ...] = ("move", "dig", "dump")
    max_speed_m_s: float = 1.0
    max_depth_m: float = 2.0
    max_volume_m3: float = 1.0
    total_volume_m3: float = 10.0
    max_actions: int = 100
    skill_destinations: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    observation_fields: tuple[str, ...] = ("target_xyz", "speed_m_s", "depth_m", "volume_m3")
    max_observation_age_s: float = 30.0
    lease_ttl_s: float = 1.0
    subject: str = "planner"
    reference_surface_z_m: float = 0.0

    def __post_init__(self):
        _text(self.mission_id, "mission_id")
        _integer(self.version, "version", 1)
        _text(self.subject, "subject")
        skills = _names(self.allowed_skills, "skills")
        object.__setattr__(self, "allowed_skills", skills)
        if not isinstance(self.destinations, Mapping) or not self.destinations:
            raise PolicyError("invalid_destinations")
        destinations = {}
        for name, box in self.destinations.items():
            _text(name, "destination")
            if not isinstance(box, AABB):
                raise PolicyError("invalid_destination_box")
            destinations[name] = box
        object.__setattr__(self, "destinations", MappingProxyType(destinations))
        routes = {}
        for skill, names in self.skill_destinations.items():
            if skill not in skills:
                raise PolicyError("unknown_skill_route")
            names = _names(names, "skill_destinations")
            if not set(names) <= set(destinations):
                raise PolicyError("unknown_destination_route")
            routes[skill] = names
        object.__setattr__(self, "skill_destinations", MappingProxyType(routes))
        for name in ("max_speed_m_s", "max_depth_m", "max_volume_m3", "total_volume_m3",
                     "max_observation_age_s", "lease_ttl_s"):
            object.__setattr__(self, name, _number(getattr(self, name), name, 0))
        if self.max_speed_m_s == 0 or self.lease_ttl_s == 0:
            raise PolicyError("zero_operational_limit")
        _integer(self.max_actions, "max_actions", 1)
        object.__setattr__(self, "reference_surface_z_m",
                           _number(self.reference_surface_z_m, "reference_surface_z_m"))
        numeric_fields = {"target_xyz", "speed_m_s", "depth_m", "volume_m3"}
        observation_fields = tuple(self.observation_fields)
        if not set(observation_fields) <= numeric_fields:
            raise PolicyError("observation_may_not_grant_authority")
        object.__setattr__(self, "observation_fields", observation_fields)

    def to_dict(self):
        return {"mission_id": self.mission_id, "version": self.version,
                "destinations": {k: v.to_dict() for k, v in self.destinations.items()},
                "allowed_skills": self.allowed_skills,
                "max_speed_m_s": self.max_speed_m_s, "max_depth_m": self.max_depth_m,
                "max_volume_m3": self.max_volume_m3, "total_volume_m3": self.total_volume_m3,
                "max_actions": self.max_actions, "skill_destinations": self.skill_destinations,
                "observation_fields": self.observation_fields,
                "max_observation_age_s": self.max_observation_age_s,
                "lease_ttl_s": self.lease_ttl_s, "subject": self.subject,
                "reference_surface_z_m": self.reference_surface_z_m}

    @property
    def contract_hash(self):
        return digest(self.to_dict())


@dataclass(frozen=True)
class Provenance:
    source_id: str
    kind: str
    fields_json: str
    mission_id: str
    observed_at: float
    signature: str = ""

    def body(self):
        return {"source_id": self.source_id, "kind": self.kind,
                "fields_json": self.fields_json, "mission_id": self.mission_id,
                "observed_at": self.observed_at}

    def to_dict(self):
        return dict(self.body(), signature=self.signature)


@dataclass(frozen=True)
class Action:
    request_id: str
    mission_id: str
    version: int
    sequence: int
    skill: str
    target_xyz: tuple[float, float, float]
    destination: str
    speed_m_s: float
    depth_m: float = 0.0
    volume_m3: float = 0.0
    frame: str = "world"
    units: str = "SI"
    provenance: tuple[Provenance, ...] = ()
    text: str = ""

    def __post_init__(self):
        for name in ("request_id", "mission_id", "skill", "destination", "frame", "units"):
            _text(getattr(self, name), name)
        _integer(self.version, "version", 1)
        _integer(self.sequence, "sequence")
        object.__setattr__(self, "target_xyz", _xyz(self.target_xyz))
        for name in ("speed_m_s", "depth_m", "volume_m3"):
            object.__setattr__(self, name, _number(getattr(self, name), name, 0))
        if not isinstance(self.provenance, (list, tuple)) or any(
                not isinstance(x, Provenance) for x in self.provenance):
            raise PolicyError("invalid_provenance")
        object.__setattr__(self, "provenance", tuple(self.provenance))
        if not isinstance(self.text, str) or len(self.text) > 32768:
            raise PolicyError("invalid_text")

    def values(self):
        return {"skill": self.skill, "target_xyz": self.target_xyz,
                "destination": self.destination, "speed_m_s": self.speed_m_s,
                "depth_m": self.depth_m, "volume_m3": self.volume_m3,
                "frame": self.frame, "units": self.units}

    def to_dict(self):
        return dict(self.values(), request_id=self.request_id, mission_id=self.mission_id,
                    version=self.version, sequence=self.sequence, text=self.text,
                    provenance=[p.to_dict() for p in self.provenance])

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]):
        if not isinstance(data, Mapping):
            raise PolicyError("action_not_object")
        if set(data) - set(cls.__dataclass_fields__):
            raise PolicyError("unknown_action_fields")
        args = dict(data)
        try:
            args["provenance"] = tuple(p if isinstance(p, Provenance) else Provenance(**p)
                                       for p in args.get("provenance", ()))
            return cls(**args)
        except (TypeError, KeyError) as exc:
            raise PolicyError("invalid_action_schema") from exc


@dataclass(frozen=True)
class Capability:
    capability_id: str
    mission_id: str
    version: int
    contract_hash: str
    subject: str
    destination_names: tuple[str, ...]
    allowed_skills: tuple[str, ...]
    budget_volume_m3: float
    max_actions: int
    max_speed_m_s: float
    max_depth_m: float
    issued_at: float
    expires_at: float
    signature: str = ""

    def body(self):
        return {name: getattr(self, name) for name in self.__dataclass_fields__
                if name != "signature"}

    def to_dict(self):
        return dict(self.body(), signature=self.signature)


class Issuer:
    """Trusted authority; keep this object and its secret outside planner process."""
    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise PolicyError("issuer_secret_requires_16_bytes")
        self.__secret = secret
        self._revoked: set[str] = set()
        self._lock = threading.RLock()

    def _sign(self, domain: str, value: Any) -> str:
        return hmac.new(self.__secret, (domain + "\n" + canonical_json(value)).encode(),
                        "sha256").hexdigest()

    def verify(self, domain: str, body: Any, signature: str) -> bool:
        return isinstance(signature, str) and hmac.compare_digest(self._sign(domain, body), signature)

    def issue_capability(self, contract: MissionContract, *, subject: str = "planner",
                         destination_names: Sequence[str] | None = None,
                         allowed_skills: Sequence[str] | None = None,
                         budget_volume_m3: float | None = None, max_actions: int | None = None,
                         max_speed_m_s: float | None = None, max_depth_m: float | None = None,
                         now: float = 0.0, ttl: float = 60.0,
                         capability_id: str | None = None) -> Capability:
        now, ttl = _number(now, "now", 0), _number(ttl, "ttl", 0)
        if ttl == 0 or subject != contract.subject:
            raise PolicyError("invalid_capability_subject_or_ttl")
        names = _names(tuple(destination_names) if destination_names is not None
                       else tuple(contract.destinations), "destination_names")
        skills = _names(tuple(allowed_skills) if allowed_skills is not None
                        else contract.allowed_skills, "allowed_skills")
        if not set(names) <= set(contract.destinations) or not set(skills) <= set(contract.allowed_skills):
            raise PolicyError("capability_must_narrow_contract")
        bounds = {}
        for key, value, upper in (
                ("budget_volume_m3", budget_volume_m3, contract.total_volume_m3),
                ("max_speed_m_s", max_speed_m_s, contract.max_speed_m_s),
                ("max_depth_m", max_depth_m, contract.max_depth_m)):
            bounds[key] = upper if value is None else _number(value, key, 0)
            if bounds[key] > upper:
                raise PolicyError("capability_must_narrow_contract")
        actions = contract.max_actions if max_actions is None else _integer(max_actions, "max_actions", 1)
        if actions > contract.max_actions:
            raise PolicyError("capability_must_narrow_contract")
        cap = Capability(_text(capability_id or secrets.token_hex(12), "capability_id"),
                         contract.mission_id, contract.version, contract.contract_hash,
                         subject, names, skills, bounds["budget_volume_m3"], actions,
                         bounds["max_speed_m_s"], bounds["max_depth_m"], now, now + ttl)
        return replace(cap, signature=self._sign("capability-v1", cap.body()))

    def label(self, source_id: str, kind: str, fields: Mapping[str, Any],
              mission_id: str, observed_at: float = 0.0) -> Provenance:
        _text(source_id, "source_id")
        _text(mission_id, "mission_id")
        if kind not in {"trusted_command", "untrusted_observation", "untrusted_document",
                        "untrusted_memory", "untrusted_peer"}:
            raise PolicyError("unknown_provenance_kind")
        if not isinstance(fields, Mapping) or not fields:
            raise PolicyError("provenance_requires_exact_field_values")
        fields = {k: _xyz(v) if k == "target_xyz" else
                  _number(v, k) if k in ("speed_m_s", "depth_m", "volume_m3") else v
                  for k, v in fields.items()}
        label = Provenance(source_id, kind, canonical_json(fields), mission_id,
                           _number(observed_at, "observed_at", 0))
        return replace(label, signature=self._sign("provenance-v1", label.body()))

    def revoke(self, capability: Capability | str):
        with self._lock:
            self._revoked.add(capability if isinstance(capability, str) else capability.capability_id)

    def is_revoked(self, capability_id: str):
        with self._lock:
            return capability_id in self._revoked


def _tube(value: Any) -> dict[str, Any] | None:
    """Validate a certified state tube {field, nominal, radius[, execution_radius]}.

    The physical certificate states that the bound motion descriptor is
    admissible for every start state whose ``field`` lies within ``radius``
    (infinity norm, per component) of ``nominal``. ``execution_radius`` bounds
    the tracking deviation that the certificate tolerates during execution.
    """
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise PolicyError("invalid_state_tube")
    field_name = _text(value.get("field"), "state_tube_field")
    nominal = value.get("nominal")
    if not isinstance(nominal, (list, tuple)) or not nominal:
        raise PolicyError("invalid_state_tube_nominal")
    nominal = [_number(x, "state_tube_nominal") for x in nominal]
    radius = value.get("radius")
    radius = ([_number(x, "state_tube_radius", 0) for x in radius]
              if isinstance(radius, (list, tuple)) else [_number(radius, "state_tube_radius", 0)] * len(nominal))
    if len(radius) != len(nominal):
        raise PolicyError("invalid_state_tube_radius")
    out = {"field": field_name, "nominal": nominal, "radius": radius}
    out["execution_radius"] = (_number(value["execution_radius"], "execution_radius", 0)
                               if value.get("execution_radius") is not None else min(radius))
    return out


def _tube_distance(tube: Mapping[str, Any], state: Any) -> float | None:
    """Largest normalized component deviation; None when the field is absent or malformed."""
    if not isinstance(state, Mapping) or tube["field"] not in state:
        return None
    try:
        values = [_number(x, "live_state") for x in state[tube["field"]]]
    except (PolicyError, TypeError):
        return None
    if len(values) != len(tube["nominal"]):
        return None
    worst = 0.0
    for v, n, r in zip(values, tube["nominal"], tube["radius"]):
        d = abs(v - n)
        worst = max(worst, d / r if r > 0 else (0.0 if d == 0 else math.inf))
    return worst


@dataclass(frozen=True)
class Lease:
    lease_id: str
    request_id: str
    action_hash: str
    trajectory_hash: str
    state_hash: str
    contract_hash: str
    capability: Capability | None
    issued_at: float
    expires_at: float
    signature: str = ""
    state_tube: Mapping[str, Any] | None = None

    def body(self):
        body = {"lease_id": self.lease_id, "request_id": self.request_id,
                "action_hash": self.action_hash, "trajectory_hash": self.trajectory_hash,
                "state_hash": self.state_hash, "contract_hash": self.contract_hash,
                "capability": self.capability.to_dict() if self.capability else None,
                "issued_at": self.issued_at, "expires_at": self.expires_at}
        if self.state_tube is not None:
            body["state_tube"] = dict(self.state_tube)
        return body


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    lease: Lease | None = None
    dispatch_status: str = "not_dispatched"


class ExecutorSink:
    """Only Gateway.commit receives the sink's private publication token.

    callback(action, trajectory, state) is the trusted actuator adapter. Records
    are copied to finite JSON, preventing later mutation of published payloads.
    Public publish/direct_publish always rejects. This is in-process mediation,
    not a claim of protection from a hostile Python process sharing memory.
    A dispatch is logged before calling the actuator adapter. Callback failure
    retains an unknown-outcome record: an exception is not proof of no actuation.
    """
    def __init__(self, callback: Callable | None = None, *, gateway: Gateway):
        if not isinstance(gateway, Gateway):
            raise PolicyError("sink_requires_designated_gateway")
        self.__gateway = gateway
        self.__token = object()
        self.__callback = callback
        self.__commands: list[dict[str, Any]] = []

    @property
    def commands(self):
        return json.loads(canonical_json(self.__commands))

    def publish(self, *args, **kwargs):
        raise PolicyError("unmediated_publish_denied")

    direct_publish = publish

    def _accept(self, token, action: Action, trajectory, state, lease: Lease):
        if token is not self.__token:
            raise PolicyError("unmediated_publish_denied")
        record = json.loads(canonical_json({"action": action.to_dict(), "trajectory": trajectory,
                                           "state": state, "lease_id": lease.lease_id,
                                           "status": "dispatch_started"}))
        self.__commands.append(record)
        try:
            if self.__callback is not None:
                self.__callback(action, trajectory, state)
        except Exception as exc:
            record["status"] = "dispatch_outcome_unknown"
            record["callback_error_type"] = type(exc).__name__
            raise DispatchOutcomeUnknown(type(exc).__name__) from exc
        record["status"] = "committed"

    def _gateway_token(self, gateway):
        if gateway is not self.__gateway:
            raise PolicyError("sink_owner_mismatch")
        return self.__token

    def _owned_by(self, gateway):
        return gateway is self.__gateway


class Gateway:
    def __init__(self, contract: MissionContract, issuer: Issuer,
                 mode: str | Mode = Mode.B4_FULL, physical_check: Callable | None = None):
        self.contract = contract
        self.issuer = issuer
        self.mode = Mode(mode)
        self.physical_check = physical_check
        self.sequence = 0
        self.total_volume_m3 = 0.0
        self.action_count = 0
        self._cap_usage: dict[str, tuple[int, float]] = {}
        self._used_requests: set[str] = set()
        self._used_leases: set[str] = set()
        self._issued_leases: set[str] = set()
        self._key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self.audit: list[dict[str, Any]] = []
        # Execution authority records for dispatched skills (lease_id -> record).
        self._active: dict[str, dict[str, Any]] = {}
        self._last_tube: dict[str, Any] | None = None
        self._versions = {contract.mission_id: contract.version}

    @property
    def full(self):
        return self.mode.value.startswith("B4_")

    @property
    def uses_tube(self):
        """Certified state tubes replace exact live-state equality (all B4 modes but EXACT_STATE)."""
        return self.full and self.mode != Mode.B4_EXACT_STATE

    def make_sink(self, callback: Callable | None = None):
        """Trusted construction: permanently binds the sink to this gateway."""
        return ExecutorSink(callback, gateway=self)

    @property
    def semantic(self):
        return self.full or self.mode in {Mode.B2_SEMANTIC, Mode.B23_SEMANTIC_PHYSICAL}

    @property
    def physical(self):
        return self.full or self.mode in {Mode.B3_PHYSICAL, Mode.B23_SEMANTIC_PHYSICAL}

    def update_contract(self, contract: MissionContract):
        """Trusted operation. New authority resets explicit per-contract budgets."""
        with self._lock:
            if contract.version <= self._versions.get(contract.mission_id, 0):
                raise PolicyError("contract_version_must_increase")
            self._versions[contract.mission_id] = contract.version
            self.contract = contract
            self.sequence = self.action_count = 0
            self.total_volume_m3 = 0.0
            self._cap_usage.clear()

    def _result(self, allowed: bool, reason: str, action: Action | None, stage: str, now,
                lease: Lease | None = None, dispatch_status: str = "not_dispatched"):
        self.audit.append({"stage": stage, "allowed": allowed, "reason": reason,
                           "request_id": action.request_id if isinstance(action, Action) else None,
                           "now": now, "mode": self.mode.value,
                           "dispatch_status": dispatch_status})
        return Decision(allowed, reason, lease, dispatch_status)

    def _semantics(self, a: Action):
        c = self.contract
        if a.mission_id != c.mission_id or a.version != c.version:
            return "mission_version_mismatch"
        if a.frame != "world" or a.units != "SI":
            return "noncanonical_frame_or_units"
        if a.skill not in c.allowed_skills:
            return "skill_not_authorized"
        if a.destination not in c.destinations:
            return "destination_not_authorized"
        if a.destination not in c.skill_destinations.get(a.skill, tuple(c.destinations)):
            return "skill_destination_not_authorized"
        if not c.destinations[a.destination].contains(a.target_xyz):
            return "endpoint_outside_authorized_region"
        # Every exposed skill moves the mechanism. Holding/stopping belongs to
        # the trusted recovery controller, not a zero-speed motion request.
        if a.speed_m_s <= 0:
            return "nonpositive_motion_speed"
        if a.speed_m_s > c.max_speed_m_s or a.depth_m > c.max_depth_m or a.volume_m3 > c.max_volume_m3:
            return "numeric_limit_exceeded"
        if a.skill == "dig":
            if a.volume_m3 <= 0:
                return "dig_requires_positive_declared_volume"
            endpoint_depth = max(0.0, c.reference_surface_z_m - a.target_xyz[2])
            if endpoint_depth > a.depth_m + 1e-12:
                return "declared_depth_inconsistent_with_reference_plane"
        if self.mode != Mode.B4_NO_FRESHNESS and a.sequence != self.sequence:
            return "sequence_mismatch"
        if self.mode != Mode.B4_NO_BUDGET:
            charge = a.volume_m3 if a.skill == "dig" else 0.0
            if self.action_count >= c.max_actions or self.total_volume_m3 + charge > c.total_volume_m3 + 1e-12:
                return "mission_budget_exceeded"
        return None

    def _provenance(self, a: Action, now: float):
        if not a.provenance:
            return "missing_provenance"
        values = a.values()
        covered = set()
        for p in a.provenance:
            if not self.issuer.verify("provenance-v1", p.body(), p.signature):
                return "provenance_signature_invalid"
            if p.mission_id != self.contract.mission_id:
                return "provenance_mission_mismatch"
            if self.mode != Mode.B4_NO_FRESHNESS and (
                    p.observed_at > now or now - p.observed_at > self.contract.max_observation_age_s):
                return "provenance_stale"
            fields = json.loads(p.fields_json)
            if not isinstance(fields, dict) or not fields:
                return "provenance_fields_invalid"
            if p.kind != "trusted_command" and p.kind not in {
                    "untrusted_observation", "untrusted_document", "untrusted_memory", "untrusted_peer"}:
                return "provenance_kind_invalid"
            for name, value in fields.items():
                if name not in values or digest(value) != digest(values[name]):
                    return "provenance_value_mismatch"
                if p.kind != "trusted_command" and name not in self.contract.observation_fields:
                    return "untrusted_authority_field"
                covered.add(name)
        if covered != set(values):
            return "incomplete_provenance"
        return None

    def _capability(self, a: Action, cap: Capability | None, now: float):
        if not isinstance(cap, Capability):
            return "missing_capability"
        if not self.issuer.verify("capability-v1", cap.body(), cap.signature):
            return "capability_signature_invalid"
        if cap.subject != self.contract.subject:
            return "capability_subject_mismatch"
        if self.mode != Mode.B4_STATIC_PERMISSIONS and (
                cap.mission_id != self.contract.mission_id or cap.version != self.contract.version
                or cap.contract_hash != self.contract.contract_hash):
            return "capability_mission_mismatch"
        if self.mode != Mode.B4_NO_REVOCATION and self.issuer.is_revoked(cap.capability_id):
            return "capability_revoked"
        if self.mode != Mode.B4_NO_FRESHNESS:
            if now < cap.issued_at or now >= cap.expires_at:
                return "capability_expired_or_not_yet_valid"
            if a.request_id in self._used_requests:
                return "request_replay"
        if self.mode != Mode.B4_NO_SCOPE:
            if a.destination not in cap.destination_names or a.skill not in cap.allowed_skills:
                return "capability_scope_exceeded"
            if a.speed_m_s > cap.max_speed_m_s or a.depth_m > cap.max_depth_m:
                return "capability_numeric_scope_exceeded"
        if self.mode != Mode.B4_NO_BUDGET:
            count, volume = self._cap_usage.get(cap.capability_id, (0, 0.0))
            if count >= cap.max_actions or volume + (a.volume_m3 if a.skill == "dig" else 0.0) > cap.budget_volume_m3 + 1e-12:
                return "capability_budget_exceeded"
        return None

    def _check(self, a: Action, cap: Capability | None, trajectory, state, now: float,
               skip_physical: bool = False):
        if self.mode == Mode.B1_FILTER_SURROGATE:
            folded = a.text.casefold()
            if any(x in folded for x in ("ignore previous", "override", "disable safety", "new permission")):
                return "lexical_filter_rejection"
        if self.semantic:
            reason = self._semantics(a)
            if reason:
                return reason
        if self.full:
            reason = self._capability(a, cap, now)
            if reason:
                return reason
            if self.mode != Mode.B4_NO_PROVENANCE:
                reason = self._provenance(a, now)
                if reason:
                    return reason
        if self.physical and not skip_physical:
            if self.physical_check is None:
                return "physical_checker_missing"
            result = self.physical_check(a, trajectory, state)
            self._last_tube = None
            if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], bool):
                info = result[1]
                if not result[0]:
                    reason = info.get("reason", "rejected") if isinstance(info, Mapping) else info
                    return "physical:" + str(reason)
                if isinstance(info, Mapping) and info.get("state_tube") is not None:
                    self._last_tube = _tube(info["state_tube"])
            elif result is not True:
                return "physical_constraint_rejected"
        return None

    def _sign_lease(self, lease: Lease):
        return hmac.new(self._key, canonical_json(lease.body()).encode(), "sha256").hexdigest()

    def validate(self, action: Action | Mapping, capability: Capability | None,
                 trajectory, state, now: float) -> Decision:
        with self._lock:
            try:
                now = _number(now, "now", 0)
                a = action if isinstance(action, Action) else Action.from_dict(action)
                action_hash, trajectory_hash, state_hash = digest(a.to_dict()), digest(trajectory), digest(state)
                if not isinstance(trajectory, (list, tuple, Mapping)) or len(trajectory) == 0:
                    raise PolicyError("empty_or_invalid_trajectory")
                self._last_tube = None
                reason = self._check(a, capability, trajectory, state, now)
                if reason:
                    return self._result(False, reason, a, "validate", now)
                tube = self._last_tube if self.uses_tube else None
                if tube is not None:
                    d0 = _tube_distance(tube, state)
                    if d0 is None or d0 > 1.0 + 1e-12:
                        return self._result(False, "validated_state_outside_certified_tube",
                                            a, "validate", now)
                lease = Lease(secrets.token_hex(16), a.request_id, action_hash,
                              trajectory_hash, state_hash, self.contract.contract_hash,
                              capability, now, now + self.contract.lease_ttl_s,
                              state_tube=MappingProxyType(tube) if tube else None)
                lease = replace(lease, signature=self._sign_lease(lease))
                self._issued_leases.add(lease.lease_id)
                return self._result(True, "approved", a, "validate", now, lease)
            except Exception as exc:
                return self._result(False, "schema_or_checker_error:" + type(exc).__name__,
                                    action if isinstance(action, Action) else None, "validate",
                                    _audit_time(now))

    def _live_state_reason(self, lease: Lease, state, live) -> str | None:
        """State binding at dispatch.

        Without a certified tube (or in B4_EXACT_STATE) the live trusted state must
        equal the validated snapshot exactly, which was the original design. With
        a tube, the live state must lie inside the set certified by the physical
        predicate; the bound snapshot itself must still match its digest.
        """
        if lease.state_tube is None or not self.uses_tube:
            if digest(live) != lease.state_hash:
                return "live_state_differs_from_validated_snapshot"
            return None
        distance = _tube_distance(lease.state_tube, live)
        if distance is None:
            return "live_state_missing_tube_field"
        if distance > 1.0 + 1e-12:
            return "live_state_outside_certified_tube"
        return None

    def commit(self, lease: Lease | None, action: Action | Mapping, trajectory, state,
               now: float, sink: ExecutorSink, live_state: Any = None) -> Decision:
        """Dispatch an approved tuple.

        ``state`` is the snapshot presented with the approval (the one that was
        validated); ``live_state`` is the current state supplied by the trusted
        state source at dispatch. It defaults to ``state`` for callers that
        validate and dispatch at the same instant.
        """
        # Linearize commit with both revocation and other gateway commits.
        # A revocation completed before this critical section cannot race past it.
        with self._lock, self.issuer._lock:
            try:
                now = _number(now, "now", 0)
                a = action if isinstance(action, Action) else Action.from_dict(action)
                live = state if live_state is None else live_state
                # All modes retain structural schema and private publication mediation.
                digest(a.to_dict()), digest(trajectory), digest(state), digest(live)
                if not isinstance(lease, Lease) or not isinstance(sink, ExecutorSink):
                    return self._result(False, "missing_lease_or_sink", a, "commit", now)
                if not sink._owned_by(self):
                    return self._result(False, "sink_owner_mismatch", a, "commit", now)
                if lease.lease_id not in self._issued_leases or not hmac.compare_digest(self._sign_lease(lease), lease.signature):
                    return self._result(False, "lease_signature_invalid", a, "commit", now)
                time_of_check = self.mode == Mode.B4_TIME_OF_CHECK
                if self.full:
                    if self.mode != Mode.B4_NO_FRESHNESS:
                        if lease.lease_id in self._used_leases or a.request_id in self._used_requests:
                            return self._result(False, "lease_or_request_replay", a, "commit", now)
                        if now < lease.issued_at or now >= lease.expires_at:
                            return self._result(False, "lease_expired", a, "commit", now)
                    if self.mode != Mode.B4_NO_BINDING and not time_of_check:
                        if lease.action_hash != digest(a.to_dict()):
                            return self._result(False, "action_changed_after_validation", a, "commit", now)
                        if lease.trajectory_hash != digest(trajectory):
                            return self._result(False, "trajectory_changed_after_validation", a, "commit", now)
                        if lease.state_hash != digest(state):
                            return self._result(False, "state_changed_after_validation", a, "commit", now)
                        if lease.contract_hash != self.contract.contract_hash:
                            return self._result(False, "contract_changed_after_validation", a, "commit", now)
                        reason = self._live_state_reason(lease, state, live)
                        if reason:
                            return self._result(False, reason, a, "commit", now)
                if not time_of_check:
                    # Every comparison rechecks its enabled constraints at execution.
                    # Baselines lack only the explicit capability/provenance/lease
                    # controls, not normal continuous semantic/physical mediation.
                    # A certified tube lets the full gateway reuse the expensive
                    # physical certificate: the bound descriptor is unchanged and
                    # the live state lies in the certified start set.
                    reuse = (self.uses_tube and lease.state_tube is not None
                             and self.mode != Mode.B4_NO_BINDING)
                    reason = self._check(a, lease.capability, trajectory, live, now, skip_physical=reuse)
                    if reason:
                        return self._result(False, reason, a, "commit", now)
                if self.full and not time_of_check:
                    # A trusted callback may synchronously change authority.
                    # Recheck after physical validation before dispatch while the
                    # issuer revocation lock remains held. Concurrent revocation
                    # linearizes before or after this whole commit transaction.
                    reason = self._semantics(a) or self._capability(a, lease.capability, now)
                    if reason:
                        return self._result(False, reason, a, "commit", now)
                    if self.mode != Mode.B4_NO_BINDING and (
                            lease.state_hash != digest(state)
                            or lease.trajectory_hash != digest(trajectory)
                            or lease.contract_hash != self.contract.contract_hash
                            or self._live_state_reason(lease, state, live)):
                        return self._result(False, "snapshot_changed_during_check", a, "commit", now)
                self._used_leases.add(lease.lease_id)
                self._used_requests.add(a.request_id)
                charge = a.volume_m3 if a.skill == "dig" else 0.0
                self.action_count += 1
                self.sequence += 1
                self.total_volume_m3 += charge
                if lease.capability is not None:
                    count, volume = self._cap_usage.get(lease.capability.capability_id, (0, 0.0))
                    self._cap_usage[lease.capability.capability_id] = count + 1, volume + charge
                # The execution authority record exists before actuation so that a
                # revocation racing with the callback is observed by supervision.
                self._active[lease.lease_id] = {
                    "request_id": a.request_id, "dispatched_at": now,
                    "capability_id": lease.capability.capability_id if lease.capability else None,
                    "capability_expires_at": lease.capability.expires_at if lease.capability else None,
                    "contract_hash": lease.contract_hash, "trajectory_hash": lease.trajectory_hash,
                    "execution_radius": (lease.state_tube or {}).get("execution_radius")}
                # Consume before actuation; callback failure cannot enable a retry.
                sink._accept(sink._gateway_token(self), a, trajectory, state, lease)
                return self._result(True, "committed", a, "commit", now, lease,
                                    dispatch_status="committed")
            except DispatchOutcomeUnknown as exc:
                return self._result(False, "dispatch_outcome_unknown:" + str(exc),
                                    a, "commit", now, lease,
                                    dispatch_status="dispatch_outcome_unknown")
            except Exception as exc:
                return self._result(False, "schema_or_executor_error:" + type(exc).__name__,
                                    action if isinstance(action, Action) else None, "commit",
                                    _audit_time(now))

    def supervise(self, lease: Lease, now: float, tracking_error: float | None = None) -> Decision:
        """Execution-time authority check, called by the trusted executor every control period.

        A dispatched skill keeps executing only while (i) its capability is
        unrevoked and unexpired, (ii) the mission contract it was admitted under is
        still current and (iii) the measured deviation from the admitted reference
        stays inside the certified execution radius. A failed check returns
        ``dispatch_status='preempt'``: the executor must switch to its certified
        stop. The planner has no interface to this method.
        """
        with self._lock, self.issuer._lock:
            lid = lease.lease_id if isinstance(lease, Lease) else None
            record = self._active.get(lid)
            if record is None:
                return Decision(False, "no_active_execution", lease, "inactive")
            reason = None
            try:
                now = _number(now, "now", 0)
                if tracking_error is not None:
                    tracking_error = _number(tracking_error, "tracking_error", 0)
            except PolicyError:
                now, reason = _audit_time(now), "invalid_supervision_input"
            if reason is not None:
                pass
            elif (self.mode != Mode.B4_NO_REVOCATION and record["capability_id"] is not None
                    and self.issuer.is_revoked(record["capability_id"])):
                reason = "capability_revoked_during_execution"
            elif record["contract_hash"] != self.contract.contract_hash:
                reason = "contract_changed_during_execution"
            elif record["capability_expires_at"] is not None and now >= record["capability_expires_at"]:
                reason = "capability_expired_during_execution"
            elif (tracking_error is not None and record["execution_radius"] is not None
                  and tracking_error > record["execution_radius"]):
                reason = "execution_left_certified_tube"
            if reason is None:
                return Decision(True, "authority_current", lease, "executing")
            del self._active[lid]
            self.audit.append({"stage": "supervise", "allowed": False, "reason": reason,
                               "request_id": record["request_id"], "now": now,
                               "mode": self.mode.value, "dispatch_status": "preempt"})
            return Decision(False, reason, lease, "preempt")

    def complete(self, lease: Lease, now: float, outcome: str = "completed") -> None:
        """Trusted executor reports the end of a dispatched skill; supervision stops."""
        with self._lock:
            record = self._active.pop(lease.lease_id if isinstance(lease, Lease) else None, None)
            if record is not None:
                self.audit.append({"stage": "complete", "allowed": True, "reason": outcome,
                                   "request_id": record["request_id"], "now": _audit_time(now),
                                   "mode": self.mode.value, "dispatch_status": outcome})

    @property
    def active_executions(self):
        with self._lock:
            return tuple(self._active)


def labelled_action(issuer: Issuer, *, observed_at: float = 0.0,
                    observation_fields: Sequence[str] = (), source_id: str = "trusted_operator",
                    **action_kwargs) -> Action:
    """Convenience for trusted test setup/transport; never expose issuer to planner."""
    a = Action(**action_kwargs)
    observations = set(observation_fields)
    if not observations <= set(a.values()):
        raise PolicyError("unknown_observation_fields")
    trusted = {k: v for k, v in a.values().items() if k not in observations}
    untrusted = {k: v for k, v in a.values().items() if k in observations}
    labels = []
    if trusted:
        labels.append(issuer.label(source_id, "trusted_command", trusted, a.mission_id, observed_at))
    if untrusted:
        labels.append(issuer.label("observation_transport", "untrusted_observation", untrusted,
                                   a.mission_id, observed_at))
    return replace(a, provenance=tuple(labels))


__all__ = ["AABB", "Action", "Capability", "Decision", "ExecutorSink", "Gateway", "Issuer",
           "Lease", "MissionContract", "Mode", "PolicyError", "Provenance", "canonical_json",
           "digest", "labelled_action"]