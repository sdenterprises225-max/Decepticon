# Working Together on Decepticon

This document describes how we collaborate day-to-day on the Decepticon OSS
repository — branch strategy, code-review flow, what triggers maintainer
review, how releases are gated, and the anti-patterns we have learned to
avoid. It complements:

- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to participate (setup, PR
  basics, code conventions)
- [RELEASE.md](../RELEASE.md) — versioning and the release-workflow
  walkthrough
- [SECURITY.md](../SECURITY.md) — how to report vulnerabilities

If you are reading this for the first time, skim sections 1–4. Sections 5
onward are reference for when something specific comes up.

---

## 1. Operating Model in One Paragraph

Decepticon is developed on a **single trunk (`main`)** using **GitHub
Flow** — short-lived feature branches, pull requests into `main`, no
permanent `dev` / `staging` / `release-x` branches. Contributors with
write access can self-merge their PRs once required CI status checks pass
and any CODEOWNERS-protected paths have been reviewed by a maintainer.
**External publishing (PyPI, GHCR, GitHub Releases) is the only step that
always requires explicit maintainer approval**, gated by the
`pypi-release` GitHub Environment.

This keeps day-to-day velocity high while preserving a hard human gate
between code landing on `main` and code reaching downstream users.

---

## 2. Roles

We do not maintain a separate roles file. The effective roles are:

- **Maintainers** — listed in [.github/CODEOWNERS](../.github/CODEOWNERS).
  Responsible for reviewing supply-chain-critical paths and approving
  release deployments. They are the required reviewer for the
  `pypi-release` environment.
- **Write contributors** — collaborators with write access on the repo.
  May open branches directly on the repo, open PRs, self-merge PRs into
  `main` once CI is green, and trigger releases by pushing `v*` tags.
- **External contributors** — anyone with a GitHub account. Contribute via
  forked-repo PRs. Same review path as write contributors, but cannot push
  branches directly to `PurpleAILAB/Decepticon`.

A contributor's role is not a level of trust; it is a question of how the
change is delivered (forked PR vs direct branch). The gates below apply
the same way regardless.

---

## 3. Branch Strategy

- `main` is the only long-lived branch. It is always intended to be
  releasable.
- Feature work happens on short-lived branches. Suggested naming:
  - `feat/<short-slug>` — new functionality
  - `fix/<short-slug>` — bug fix
  - `chore/<short-slug>` — tooling / CI / housekeeping
  - `docs/<short-slug>` — docs-only
  - `refactor/<short-slug>` — internal restructure with no behavior change
- Delete the branch after merge.
- We **do not** maintain a `dev` or `staging` branch. If you need to stage
  a multi-PR feature, land each PR behind a feature flag or behind an
  unimplemented entry point so partial progress on `main` is harmless.
- We **do not** cut long-lived release branches. The repo state at tag
  `vX.Y.Z` is the release. Hotfixes for an already-released line are
  handled by tagging a new patch from `main` after a forward fix lands.

---

## 4. Pull Request Workflow

### 4.1 Opening a PR

1. Branch off the latest `main`.
2. Make the change. Run the relevant local gates from the
   [Makefile](../Makefile) before you push — at minimum the lane that
   matches what you changed:
   ```bash
   make quality        # PR-gate mirror: Python + CLI + Web lint/typecheck/test
   make ci-lint        # just lint + typecheck
   make ci-test        # just tests
   ```
   These mirror the GitHub Actions CI lane exactly; the Makefile is the
   single source of truth.
3. Open the PR against `main`. Use a Conventional-Commit-style title
   (`type(scope): description`) — this is what CONTRIBUTING.md and the
   commit log already follow.
4. Fill in the PR description: what changed and **why**. Linked issues,
   reproduction context for bug fixes, and breaking-change notes belong
   here.

### 4.2 What CI runs

Required status checks for `main` (enforced by repository ruleset):

- **Python (lint + typecheck + test)** — `make ci-lint` + `make ci-test`
- **CLI (ubuntu-latest)** / **CLI (macos-latest)** — typecheck + build +
  test for the Ink CLI
- **Web (lint + build)** — Prisma generate, ESLint, Next.js build
- **Security (pip-audit + gitleaks)** — dependency CVE scan + leaked
  secret detection

If any of these fail, the PR cannot merge. If any are flaky, fix the
flake — do not paper over it by re-running.

### 4.3 Review and CODEOWNERS

Most PRs are **self-mergeable once CI is green** — no formal review
required. This is intentional: it keeps day-to-day work fast.

`.github/CODEOWNERS` carves out a small set of paths where a maintainer
review **is** required because the blast radius of a mistake is large.
Today those are:

| Path | Why it needs maintainer review |
|------|--------------------------------|
| `.github/workflows/**`, `.github/actions/**`, `.github/CODEOWNERS` | These files define what happens in CI and what gates a release; a malicious or careless change here can disable every other gate in the repo. |
| `pyproject.toml`, `packages/*/pyproject.toml`, `uv.lock`, `package.json`, `package-lock.json`, `go.mod`, `go.sum`, `.goreleaser.yaml` | These control what ends up published to PyPI, npm, and the launcher binaries. A pinned-dep change is a supply-chain change. |
| `packages/decepticon-core/decepticon_core/contracts/**`, `protocols/**`, `registry/**` | The public plugin API surface. Plugin authors build against these; breakages cascade. |
| `scripts/install.sh` | Executed by users with `curl \| bash`. One-shot RCE surface. |
| `docker-compose.yml`, `containers/*.Dockerfile` | Defines the runtime stack every user spins up. |

If your PR touches one of these paths, expect to wait for a maintainer
review. Everything else can land on green CI.

The `dismiss_stale_reviews_on_push` policy means **any new commit
invalidates prior approvals** — review is on the exact tree being merged,
not on an earlier version.

### 4.4 Merging

- **Use squash merge** by default. Use merge-commit only when the branch
  represents a coherent series of independently meaningful commits
  (uncommon).
- Delete the branch after merge.
- Do **not** force-push to `main`, delete `main`, or rewrite published
  history — the ruleset blocks deletion / non-fast-forward updates of
  `main`. The same ruleset blocks deletion / update / non-fast-forward
  of any `v*` tag once created.

### 4.5 Anti-patterns we reject on sight

These are written here because each one has caused real damage in the
past, not as theoretical hygiene.

- **Mega-PRs that bundle unrelated work** — for example, "merge all open
  PRs", "integrate the backlog", "consolidated branch". They hide review
  surface, corrupt blame history, and have shipped regressions before.
  Land each PR individually. If two PRs genuinely depend on each other,
  say so in the description.
- **AI co-author trailers** (`Co-Authored-By: Claude`,
  `Co-Authored-By: Copilot`, etc.) on commits. They are not used in this
  repo and will be stripped. Use the assistant for help; commit under
  your own identity.
- **Skipping hooks** (`--no-verify`, `--no-gpg-sign`) without explicit
  maintainer agreement. If a hook fails, fix the underlying issue.
- **Bypassing CI** by editing or removing required checks in the same PR.
  CI / workflow changes go in a CODEOWNERS-reviewed PR of their own.

---

## 5. Releases

The release process is documented end-to-end in
[RELEASE.md](../RELEASE.md). This section covers only the **collaboration
gate** — who approves what, and where the human-in-the-loop step lives.

### 5.1 The gate

`.github/workflows/release.yml` triggers on `push: tags: ["v*"]`. Every
job in that workflow that produces an externally-visible artifact
declares `environment: pypi-release`:

- `publish-pypi` — three workspace wheels to PyPI via Trusted Publishing
- `launcher` — GoReleaser binaries + config-checksums manifest attached
  to the GitHub Release
- `docker`, `docker-heavy`, `docker-heavy-merge`, `docker-web`,
  `docker-web-merge` — multi-arch image builds, GHCR pushes, cosign
  keyless signing, CycloneDX SBOM generation and attestation
- `publish-release` — promotes `:<version>` → `:latest` and undrafts the
  GitHub Release

The `pypi-release` environment requires approval from a maintainer
(`PurpleCHOIms` today; see CODEOWNERS for the canonical list) before any
of these jobs can start their `runs-on` block. The deployment branch
policy on this environment is restricted to `refs/tags/v*`, so the
environment cannot be invoked from `workflow_dispatch` on `main` or any
non-tag ref.

`.github/workflows/release-recover.yml` (the `workflow_dispatch` recovery
path used to re-promote `:latest` after a partial-failure rerun) is
gated by the same environment for the same reason.

### 5.2 What a contributor sees

1. You land your fixes on `main` via normal PRs.
2. You (or a maintainer) push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. The Release workflow starts and **immediately pauses** on every gated
   job, showing pending deployments in the "Review deployments" widget
   on the workflow-run page.
4. A maintainer reviews the pending deployments and approves them. Builds
   then proceed and publish externally.
5. If anything looks wrong at step 3 — wrong tag, wrong commit, wrong
   moment — a maintainer rejects the deployment. Nothing leaves the repo.
   Delete the tag and start over once the issue is fixed. (Note: the
   `tag-immutability-v` ruleset blocks deletion of a tag once
   created — only organization admins can bypass this, and only for
   recovery from a botched tag.)

### 5.3 Supply chain

These are baked into `release.yml` and do not require contributor action,
but you should know they exist so you can verify a release artifact:

- **PyPI Trusted Publishing (OIDC)** — no long-lived API token. The PyPI
  side also requires the OIDC token to come from the `pypi-release`
  environment; defense in depth in case the `environment:` line is ever
  removed from `release.yml`.
- **Cosign keyless signing** — every GHCR image and multi-arch manifest
  is signed via Sigstore. Verify with:
  ```bash
  cosign verify ghcr.io/purpleailab/<image>:<version> \
    --certificate-identity-regexp 'https://github\.com/PurpleAILAB/Decepticon/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```
- **CycloneDX SBOMs** — generated by `anchore/sbom-action` for each
  image and attested to the OCI artifact via `cosign attest`. Also
  uploaded as workflow artifacts.
- **Config-checksums manifest** — `docker-compose.yml`,
  `config/litellm.yaml`, and `.env.example` get a sha256 manifest
  attached to the GitHub Release. The launcher and install script
  verify against this before writing user files. Treat this as the
  source of truth for those three files; do not fetch them from
  `raw.githubusercontent.com/main` for production use.

---

## 6. Communication

- **Bugs**: open an issue using the Bug Report template.
- **Features / design discussion**: Feature Request template, or open a
  draft PR with a design sketch in the description.
- **Security**: do **not** open a public issue. Follow
  [SECURITY.md](../SECURITY.md).
- **Release-blocking questions**: leave them on the PR or issue in
  question; do not DM maintainers about open-source release decisions.

---

## 7. Changing This Document

This file is `.github/CODEOWNERS`-protected indirectly — it lives outside
the protected paths, so any contributor can propose a change. But because
it codifies how the project is operated, please open the change as a PR
with a description that explains what is changing and why, and tag a
maintainer for review even though it is not strictly required.
