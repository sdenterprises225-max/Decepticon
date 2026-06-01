# WAVE-4 §4.2 — Sandbox-per-engagement isolation (design)

> Deliberately deferred from implementation because it touches the Go
> launcher's compose orchestration, which is risky to change without
> maintainer coordination. This doc captures the design so the
> implementation work is short when greenlit.

## Problem

[docker-compose.yml#L138-L172](file:///C:/Users/Admin/Decepticon/docker-compose.yml)
defines **one** `sandbox` service per stack. Two concurrent engagements
share the same `/workspace`, the same tmux server, the same FastAPI
daemon, and the same PID namespace. You cannot run "Web2 audit" and
"Web3 audit" simultaneously.

The `DECEPTICON_STACK_NAME` knob is for multi-host (run two stacks on
the same Docker host); it does not address multi-engagement on a single
stack.

## Goals

1. Each engagement gets its own sandbox container with its own
   `/workspace` bind, tmux server, daemon port, and PID limits.
2. The launcher spawns sandboxes lazily (first time an engagement
   needs one) and tears them down on `decepticon end` or after an
   idle timeout.
3. Sandboxes are named deterministically so `decepticon logs <eng>`,
   `decepticon stop <eng>`, `decepticon status` all work.
4. Resource caps are per-engagement so a runaway engagement cannot
   starve neighbors (CPU shares, memory limit, PID limit).
5. Existing single-engagement workflows still work identically.

## Design

### Container naming

```
decepticon${DECEPTICON_STACK_NAME:+-${DECEPTICON_STACK_NAME}}-sandbox-${ENGAGEMENT_SLUG}
```

The current compose `sandbox` service stays in place (it serves the
default / no-engagement-picked case for `make benchmark` and the
benchmark harness). Engagement-specific sandboxes are spawned outside
compose, via `docker create` from the launcher.

### Lifecycle: launcher additions

New launcher commands:

- `decepticon sandbox start <engagement>` — create + start the
  engagement-specific sandbox.
- `decepticon sandbox stop <engagement>` — stop + remove it.
- `decepticon sandbox list` — show running engagement sandboxes with
  their resource usage.

The existing `decepticon start` flow gets a single addition: after the
engagement picker fires, the launcher calls `decepticon sandbox start`
internally and exports the engagement-specific sandbox daemon URL
(`SAAS_SANDBOX_URL`) for the langgraph container to use.

### Resource caps

Per-engagement defaults configurable via:

```
DECEPTICON_SANDBOX_PER_ENG_CPUS=2.0
DECEPTICON_SANDBOX_PER_ENG_MEMORY=4g
DECEPTICON_SANDBOX_PER_ENG_PIDS=4096
```

Same `--init: true` for tini, same network `sandbox-net`, same
`/workspace` bind structure (just with the engagement-slug subdirectory).

### Idle timeout

A small `decepticon-sandbox-janitor` runs as part of the launcher (Go
goroutine) and reaps sandboxes idle for > `DECEPTICON_SANDBOX_IDLE_TIMEOUT`
(default 1 hour). Idle = no HTTP traffic to its daemon for the window.

### Network policy

All engagement sandboxes share `sandbox-net` (so cross-engagement
findings can still reach Neo4j on the management plane via the
dual-homed bridge). Cross-engagement traffic between two sandboxes is
prevented at the application level (each sandbox's daemon only knows
its own engagement's port).

### Backwards compatibility

When `DECEPTICON_SANDBOX_PER_ENGAGEMENT=false` (the default for now),
nothing changes. Operators opt in via the env var or via the launcher's
`decepticon onboard` wizard.

## Implementation checklist

- [x] `clients/launcher/cmd/sandbox.go` — new Cobra subcommand with
      start/stop/list.
- [x] `clients/launcher/internal/sandbox/lifecycle.go` — opt-in direct
      Docker lifecycle for engagement-specific sandboxes.
- [x] `clients/launcher/cmd/start.go` — honors
      `DECEPTICON_SANDBOX_PER_ENGAGEMENT`, exports `SAAS_SANDBOX_URL`,
      rotates a per-engagement Neo4j user, then starts the dedicated
      sandbox after the base stack is healthy.
- [x] `docker-compose.yml` — LangGraph accepts `SAAS_SANDBOX_URL` from
      the launch environment, falling back to `http://sandbox:9999`.
- [x] `containers/sandbox.Dockerfile` — no changes (the image is
      already engagement-agnostic; only the bind mount differs).
- [x] `containers/sandbox-entrypoint.sh` — avoids chmodding
      `/workspace/.secrets` so per-engagement Cypher tokens stay private.
- [x] Tests in `clients/launcher/internal/sandbox/lifecycle_test.go`.

## Estimated effort

5-7 days when unblocked. The actual code is straightforward; the bulk
of the work is verification across the launcher's existing flows
(onboard, start, logs, stop, status) to make sure they all still work
in the per-engagement world.
