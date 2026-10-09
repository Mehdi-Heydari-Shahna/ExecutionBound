"""Connect an externally supplied model and executor to the authorization core."""
from __future__ import annotations

from typing import Any, Mapping, Protocol

from .policy import (
    Action,
    Decision,
    Gateway,
    Issuer,
    Lease,
    MissionContract,
    Mode,
    PolicyError,
    canonical_json,
)


class ModelAdapter(Protocol):
    """Trusted model interface; implementations are supplied by the caller.

    ``plan`` returns a nonempty finite JSON trajectory descriptor. Include the
    model identity/version and all execution parameters in that descriptor.
    ``physical_check`` verifies the action, trajectory and supplied state
    together. Return a boolean or ``(allowed, information)``; an optional
    ``information['state_tube']`` must be justified by the model's certificate.
    ``execute`` publishes exactly the approved descriptor to the controller.
    The controller must handle stopping when supervision returns ``preempt``.
    """

    def plan(self, action: Action, state: Any) -> Any:
        ...

    def physical_check(
        self, action: Action, trajectory: Any, state: Any
    ) -> bool | tuple[bool, Mapping[str, Any]]:
        ...

    def execute(self, action: Action, trajectory: Any, state: Any) -> None:
        ...


class ModelGateway(Gateway):
    """Full gateway with trajectory, physical-check and execution adapters.

    Call ``plan``, inherited ``validate``, and then ``dispatch`` with the same
    action, trajectory and validated state. Supply the current trusted state
    separately at dispatch. Inherited ``supervise`` and ``complete`` manage
    active execution authority.
    """

    def __init__(self, contract: MissionContract, issuer: Issuer, model: ModelAdapter):
        for name in ("plan", "physical_check", "execute"):
            if not callable(getattr(model, name, None)):
                raise PolicyError("model_requires_" + name)
        self.model = model
        super().__init__(contract, issuer, mode=Mode.B4_FULL,
                         physical_check=model.physical_check)
        self.sink = self.make_sink(model.execute)

    def plan(self, action: Action | Mapping[str, Any], state: Any) -> Any:
        """Generate a descriptor using the supplied model; grant no authority."""
        candidate = action if isinstance(action, Action) else Action.from_dict(action)
        canonical_json(state)
        trajectory = self.model.plan(candidate, state)
        canonical_json(trajectory)
        if not isinstance(trajectory, (list, tuple, Mapping)) or not trajectory:
            raise PolicyError("empty_or_invalid_trajectory")
        return trajectory

    def dispatch(
        self,
        lease: Lease | None,
        action: Action | Mapping[str, Any],
        trajectory: Any,
        state: Any,
        now: float,
        *,
        live_state: Any,
    ) -> Decision:
        """Commit through the designated executor with an explicit live state."""
        return self.commit(lease, action, trajectory, state, now, self.sink,
                           live_state=live_state)


__all__ = ["ModelAdapter", "ModelGateway"]
