# Execution-Bound Authorization

**From LLM Plans to Authorized Motion: Execution-Bound Authorization for Excavators**

Mehdi Heydari Shahna · Seihun Kim · Soyi Jung · Soohyun Park · Jouni Mattila · Joongheon Kim

An LLM-directed excavator can execute mechanically feasible motion whose destination or authority no longer matches the operator's approval. Execution-bound authorization covers the approval–dispatch–execution interval: a one-use lease binds the action, the generated motion, the mission contract and the admission tolerance; atomic dispatch rechecks current authority and measured joint drift; and periodic supervision detects revocation and requests a quintic stop with a carry-pitch endpoint.

This repository provides the authorization gateway (`secure_gateway`), the manuscript and the accompanying video.

## Repository contents

| Path | Content |
|---|---|
| `ExecutionBound_Algorithm/secure_gateway/` | Mission/lease gateway, atomic dispatch and execution supervision |
| `docs/execution_bound_authorization.pdf` | Manuscript |
| `videos/execution_bound_authorization.mp4` | Video (1 min 42 s) |

## Main components

| Paper | Code |
|---|---|
| Versioned mission contract | `MissionContract`, `AABB` |
| Expiring, revocable capability | `Issuer.issue_capability`, `Issuer.revoke`, `Capability` |
| Provenance MACs on exact field values | `Issuer.label`, `Provenance`, `labelled_action` |
| Authorization and physical predicate at validation | `Gateway.validate` |
| One-use lease with admission tolerance | `Lease` with a certified `state_tube` |
| Atomic dispatch (Table I, steps 1–5) | `Gateway.commit`, `ModelGateway.dispatch` |
| Exclusive actuator-command sink | `ExecutorSink` |
| Periodic supervision (Table I, step 6) | `Gateway.supervise`, which returns `preempt` on authority loss or tube exit |
| Strict parsing of planner output | `parse_candidate` |

Model-specific parts connect through the `ModelAdapter` interface: `plan` generates the motion descriptor, `physical_check` evaluates the physical predicate and can return the certified admission tube, and `execute` publishes the approved descriptor to the controller. When `supervise` returns `preempt`, the executor switches to its checked stop.

Following the paper's threat model, the operator, issuer, contract store, motion generator, physical certifier, state and clock sources, gateway and executor form the trusted base; planner context, proposed actions and dispatch requests are treated as untrusted.

### Gateway configurations

`Mode` selects the 14 gateway configurations compared in the interface suite of the paper:

| Paper | `Mode` |
|---|---|
| B0 (unchecked) | `B0` |
| B1 (lexical prompt filter) | `B1_FILTER_SURROGATE` |
| B2 (schema and mission limits) | `B2_SEMANTIC` |
| B3 (physical checks) | `B3_PHYSICAL` |
| B23 (B2 and B3) | `B23_SEMANTIC_PHYSICAL` |
| TOC (check-then-dispatch) | `B4_TIME_OF_CHECK` |
| DB-exact (exact state equality at dispatch) | `B4_EXACT_STATE` |
| EB (complete method) | `B4_FULL` |
| −prov., −scope, −fresh., −revoc., −bind. | `B4_NO_PROVENANCE`, `B4_NO_SCOPE`, `B4_NO_FRESHNESS`, `B4_NO_REVOCATION`, `B4_NO_BINDING` |
| static (static permissions) | `B4_STATIC_PERMISSIONS` |

`B4_NO_BUDGET` disables the mission and capability budget checks.

## Getting started

The package uses only the Python standard library (Python 3.8 or newer); no installation is required. Save the example below as `example.py` inside `ExecutionBound_Algorithm/` and run `python example.py` from that folder.

```python
import secrets

from secure_gateway import AABB, Issuer, MissionContract, ModelGateway, labelled_action


class ToyExcavator:
    """Illustrative model adapter: motion generation, physical check, actuation."""

    def plan(self, action, state):
        return {"model": "toy-v1", "skill": action.skill,
                "target_xyz": list(action.target_xyz), "duration_s": 6.0}

    def physical_check(self, action, trajectory, state):
        # A real adapter evaluates the sampled loop-closure, joint, stroke and
        # flow checks here and certifies the admission tolerance as a state tube.
        tube = {"field": "joints", "nominal": state["joints"],
                "radius": 0.1, "execution_radius": 0.1}
        return True, {"state_tube": tube}

    def execute(self, action, trajectory, state):
        print("executing", action.skill, "->", action.destination)


issuer = Issuer(secrets.token_bytes(32))          # trusted; never exposed to the planner
contract = MissionContract(
    mission_id="site-A", version=1,
    destinations={"dump_site": AABB((4.0, -1.0, 0.0), (6.0, 1.0, 3.0))})
capability = issuer.issue_capability(contract, now=0.0, ttl=60.0)
gateway = ModelGateway(contract, issuer, ToyExcavator())

action = labelled_action(issuer, request_id="r-1", mission_id="site-A", version=1,
                         sequence=0, skill="dump", target_xyz=(5.0, 0.0, 2.0),
                         destination="dump_site", speed_m_s=0.5)
state = {"joints": [0.0, 0.2, -0.4, 0.3]}

trajectory = gateway.plan(action, state)
approval = gateway.validate(action, capability, trajectory, state, now=1.0)
print(approval.allowed, approval.reason)             # True approved

live = {"joints": [0.01, 0.2, -0.4, 0.3]}            # measured state at dispatch
result = gateway.dispatch(approval.lease, action, trajectory, state,
                          now=1.5, live_state=live)
print(result.allowed, result.reason)                 # True committed

issuer.revoke(capability)                            # operator withdraws permission
check = gateway.supervise(approval.lease, now=2.0)
print(check.reason, check.dispatch_status)           # capability_revoked_during_execution preempt
```

A second dispatch with the same lease is rejected (`lease_or_request_replay`), as is a dispatch whose measured state lies outside the certified tube (`live_state_outside_certified_tube`).

## Video

[Video](videos/execution_bound_authorization.mp4) — replays of recorded MuJoCo simulations with continuum soil, comparing the execution-bound gateway (EB) with alternative gates in five scenarios: an injected destination (B3), site closure between approval and dispatch (TOC), site closure while the loaded skill runs (dispatch-only gate), stopping a loaded swing (EB-hold) and closure during discharge (EB-brake).

## Paper and citation

Please cite the accompanying manuscript when using this work:

Mehdi Heydari Shahna, Seihun Kim, Soyi Jung, Soohyun Park, Jouni Mattila, and Joongheon Kim. **From LLM Plans to Authorized Motion: Execution-Bound Authorization for Excavators.** 2026. [Manuscript](docs/execution_bound_authorization.pdf).

The excavator experiments use the mechanism and actuator interfaces of [RoboCompiler](https://github.com/Mehdi-Heydari-Shahna/RoboCompiler).

## License

The source code in `ExecutionBound_Algorithm/` is released under the Apache License 2.0 (see [LICENSE](LICENSE)). The license does not cover the manuscript or the video.
