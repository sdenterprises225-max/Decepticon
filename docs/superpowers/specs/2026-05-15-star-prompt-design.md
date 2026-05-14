# Design: GitHub Star Prompt

**Status**: approved, ready for implementation plan
**Date**: 2026-05-15
**Targets**: macOS + WSL only
**Author**: brainstormed by maintainer

## Problem

Decepticon has no in-product mechanism to invite users to star the GitHub
repository. Stars are a meaningful signal for an OSS red team framework's
discoverability and contributor confidence. We need a prompt that:

- Surfaces once during the natural onboarding moment.
- Falls through silently for users who have already starred.
- Never blocks a working `decepticon` invocation.
- Respects the explicit "Y/N at launch before engagement picker" UX direction
  already established by `PromptIfUpdateAvailable`.
- Does not require `gh` CLI to be installed but uses it for in-place star and
  skip-when-already-starred detection when present.

## Scope

In scope:
- A new internal package `clients/launcher/internal/starprompt/`.
- Two call sites: end of `onboard.go` and after `PromptIfUpdateAvailable` in `start.go`.
- Acknowledgement via a sentinel file at `~/.decepticon/.starred`.
- macOS + WSL platform support for browser-open fallback.

Out of scope (YAGNI):
- JSON metadata in the ack file (sentinel is enough).
- `DECEPTICON_NO_STAR_PROMPT` env var (a `touch ~/.decepticon/.starred` does the same).
- Multi-language UI (launcher is English).
- Telemetry of star count or prompt outcomes.
- "Remind me later" option (Skip = permanent ack — simpler).
- Native Windows / native Linux (target = macOS + WSL).
- Direct integration in `scripts/install.sh` (the launcher's onboard step picks up the install path naturally).

## Design

### Components

New package `clients/launcher/internal/starprompt/`:

| File | Purpose |
|------|---------|
| `starprompt.go` | Public entry `PromptIfNotStarred()` and the flow logic |
| `gh.go` | `gh` CLI detection + API wrappers (`ghReady`, `checkStarStatus`, `starViaGh`) |
| `browser.go` | `openBrowserToRepo()` with macOS / WSL branches |
| `starprompt_test.go` | Mock-driven coverage of every flow path |

### Call sites

1. **`clients/launcher/cmd/onboard.go`** — at the very end of the onboarding
   flow, after `.env` is written and the success message is printed, before
   the "Run 'decepticon' to start." dim text.
2. **`clients/launcher/cmd/start.go`** — immediately after the
   `PromptIfUpdateAvailable` call (currently at line 126), before the
   `engagement.Select` call.

Both sites call the same `starprompt.PromptIfNotStarred()`. The function is
idempotent: if `~/.decepticon/.starred` already exists, it returns immediately.
This is what makes the dual call site safe — `start.go`'s call is a no-op for
fresh installs (the onboard call has already created the ack file).

### Core flow

```
PromptIfNotStarred()
  │
  ├── ~/.decepticon/.starred exists?  ─── yes ──→ return
  │
  ├── stdin is TTY?  ─── no ──→ return (no ack, retry next interactive launch)
  │
  ├── `gh` binary present AND authenticated to github.com?
  │     │
  │     ├── yes: query `gh api /user/starred/PurpleAILAB/Decepticon`
  │     │         │
  │     │         ├── 204 (starred) ───→ touch ack, return silently
  │     │         ├── 404 (not starred) ──→ promptViaGh()
  │     │         └── unknown (error / timeout) ──→ promptViaBrowser()
  │     │
  │     └── no ───→ promptViaBrowser()
  │
  └── (returned from one of the two prompt paths)
```

### `promptViaGh`

```
Huh.NewConfirm()
  Title:        "★ Star Decepticon on GitHub?"
  Description:  "Detected gh CLI — we can star the repo in-place.
                 https://github.com/PurpleAILAB/Decepticon"
  Affirmative:  "Yes, star now"
  Negative:     "Skip"

  user picks "Yes":
    run `gh api -X PUT /user/starred/PurpleAILAB/Decepticon`
      success ──→ "★ Starred. Thank you!" + touch ack
      failure ──→ "gh API call failed — opening browser instead."
                  → openBrowserToRepo() + touch ack

  user picks "Skip":
    touch ack (permanent; Skip = "Don't ask again")
```

### `promptViaBrowser`

```
Huh.NewConfirm()
  Title:        "★ Star Decepticon on GitHub?"
  Description:  "Opens https://github.com/PurpleAILAB/Decepticon in your browser."
  Affirmative:  "Yes, open"
  Negative:     "Skip"

  user picks "Yes":
    openBrowserToRepo()
      success ──→ (browser opens) + touch ack
      failure ──→ "Please open: https://github.com/PurpleAILAB/Decepticon"
                  + touch ack

  user picks "Skip":
    touch ack
```

### `gh` detection details

```go
func ghReady() bool {
    if _, err := exec.LookPath("gh"); err != nil {
        return false
    }
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, "gh", "auth", "status",
                               "--hostname", "github.com")
    cmd.Stdout = io.Discard
    cmd.Stderr = io.Discard
    return cmd.Run() == nil
}

func checkStarStatus() starStatus {
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    cmd := exec.CommandContext(ctx, "gh", "api",
                               "/user/starred/PurpleAILAB/Decepticon",
                               "--silent")
    err := cmd.Run()
    if err == nil {
        return statusStarred
    }
    var exitErr *exec.ExitError
    if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
        return statusNotStarred
    }
    return statusUnknown
}

func starViaGh() error {
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    return exec.CommandContext(ctx, "gh", "api", "-X", "PUT",
                               "/user/starred/PurpleAILAB/Decepticon",
                               "--silent").Run()
}
```

The 3-second `CommandContext` deadline on every `gh` call ensures the user's
launch flow can never be blocked by a stalled subprocess.

### Browser open (macOS + WSL only)

```go
func openBrowserToRepo() error {
    const url = "https://github.com/PurpleAILAB/Decepticon"

    if runtime.GOOS == "darwin" {
        return exec.Command("open", url).Start()
    }

    if platform.IsWSL() {
        if _, err := exec.LookPath("wslview"); err == nil {
            return exec.Command("wslview", url).Start()
        }
        // WSL2 Windows interop guarantees cmd.exe on PATH at
        // /mnt/c/Windows/System32/cmd.exe.
        return exec.Command("cmd.exe", "/c", "start", url).Start()
    }

    // Native Linux is outside the supported target, but `xdg-open` is the
    // sensible no-op fallback so a launcher built on a native Linux dev
    // box still works.
    return exec.Command("xdg-open", url).Start()
}
```

`platform.IsWSL()` is already used by `cmd/start.go:26` (`isWSLFn`), so
reusing it keeps the WSL-detection logic in one place.

### Test strategy

Inject every external dependency as a function variable (the same pattern PR
#193 introduced for `executableFn`):

```go
var (
    ghReadyFn         = ghReady
    checkStarStatusFn = checkStarStatus
    starViaGhFn       = starViaGh
    openBrowserFn     = openBrowserToRepo
    isInteractiveFn   = isInteractiveStdin
)
```

Tests then swap these in `t.Cleanup`-guarded helpers and exercise:

| Scenario | Expectation |
|----------|-------------|
| `~/.decepticon/.starred` already exists | Immediate return, zero subprocess calls |
| Non-TTY stdin (CI / piped) | Immediate return, no ack file written |
| `gh` not present → user picks Yes (browser) | `openBrowser` called, ack written |
| `gh` not present → user picks Skip | ack written, no subprocess calls |
| `gh` present, not authenticated | Falls through to browser path |
| `gh` authenticated, already starred | Silent ack, no prompt shown |
| `gh` authenticated, not starred, user picks Yes | `starViaGh` called, success message, ack written |
| `gh` authenticated, not starred, user picks Yes, PUT fails | Fallback to browser, ack written |
| `gh` authenticated, not starred, user picks Skip | ack written |
| `gh` 3s timeout on status check | Returns `statusUnknown`, falls through to browser |
| `openBrowserToRepo` returns error | URL printed instead, ack still written |
| macOS / WSL platform branches | `runtime.GOOS == "darwin"` and `platform.IsWSL()` paths both covered via injection |

### Edge cases and safety

| Risk | Mitigation |
|------|------------|
| `gh` subprocess hangs | 3-second `CommandContext` deadline on every call |
| `gh auth status` only authenticated to a non-github.com host (Enterprise) | `--hostname github.com` makes the check explicit |
| PUT fails because the user's `gh` token is missing the right scopes | Exit code 1 → fall through to browser |
| Network down during `gh api` | Returns error → `statusUnknown` → browser fallback |
| Launcher invoked inside a container or under `docker exec -it` | `isInteractiveStdin()` returns false → silent skip |
| `~/.decepticon/` is unwritable | `touch ack` fails → log a warning, continue. Next interactive launch retries (idempotent). |
| User stars then later unstars | We do not detect this — intentional. The user made the choice. |
| User wants to reset the prompt | `rm ~/.decepticon/.starred` — visible from a shell, no hidden state. |

### Acknowledgement file format

A zero-byte sentinel file at `~/.decepticon/.starred`. Presence is the signal;
contents are intentionally empty. No JSON, no timestamps, no telemetry.

### Position in `start.go`

After the merge, `start.go`'s relevant region looks like:

```go
// 2.5 — Interactive update prompt (existing).
if _, err := updater.PromptIfUpdateAvailable(version); err != nil {
    ui.Warning("Update check: " + err.Error())
}

// 2.6 — Interactive star prompt (new).
starprompt.PromptIfNotStarred()

// 3 — Engagement picker (existing).
choice, err := engagement.Select(home)
```

Both prompts run before the engagement picker, so all "global decisions" land
in one place. Both are first-launch-only after their respective ack files are
written.

### Position in `onboard.go`

The new call sits as the final step of the onboard flow, after the
`Onboarding complete!` success line, before the `Run 'decepticon' to start.`
dim hint. Concretely:

```go
ui.Success("Onboarding complete!")
starprompt.PromptIfNotStarred()  // new
ui.DimText("Run 'decepticon' to start.")
```

This means a fresh install via the onboard wizard sees the star prompt
immediately after their first successful configuration — the natural ack
moment. By the time `decepticon start` runs, the ack file exists and the
`start.go` call is a no-op.

## Risks / open questions

- **`wslview` availability**: not every WSL install has it. The `cmd.exe /c
  start` fallback covers WSL2 setups with Windows interop enabled, which is
  the default. If a user has WSL2 with interop disabled, the browser open
  fails and we print the URL — acceptable.
- **`gh` version skew**: the `--silent` flag and `--hostname` filter are stable
  flags in `gh` ≥ 2.x (current is 2.x). Older `gh` would simply return an
  unexpected exit code → we treat as `statusUnknown` and fall through. No
  hard version check.
- **Star action correctness**: `gh api -X PUT /user/starred/...` is the
  documented endpoint and returns 204 on success. No retry needed; a failure
  triggers the browser fallback.

## Acceptance criteria

- A fresh install (no `~/.decepticon/.starred`) running through `decepticon`
  onboard sees the prompt exactly once.
- A subsequent `decepticon start` does not re-prompt.
- `rm ~/.decepticon/.starred && decepticon` re-prompts.
- A user with `gh` authenticated and the repo already starred is never shown
  the prompt (ack is written silently on first launch after upgrade).
- A CI invocation (`decepticon < /dev/null` or similar) never shows the prompt
  and never writes the ack file.
- `decepticon` start is never blocked by a hung `gh` call (3s deadline).

## Refs

- Launcher update prompt precedent: `clients/launcher/internal/updater/`
  (`PromptIfUpdateAvailable`, `ApplyUpdate`).
- DI injection pattern: PR #193, `executableFn` (now at top of `updater.go`).
- WSL detection: `clients/launcher/internal/platform/IsWSL`, used by
  `cmd/start.go:26`.
- Onboard wizard: `clients/launcher/cmd/onboard.go`.
