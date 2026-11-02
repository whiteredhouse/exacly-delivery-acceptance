# Bounded native merge trial

This runbook prepares one positive native protected-merge case in
`whiteredhouse/exacly-delivery-acceptance` (repository ID `1442278205`). The
`create-canary` mode prepares a data-only pull request. It does not run the native
merge engine or grant merge authority. Its source, tests and actual hosted result
must be reviewed before calling PR preparation complete.

The execution host has not been selected. A complete runtime approval packet
cannot yet be assembled: its real journal, key, runtime, fresh credential and
approval identities are still unavailable. Do not fill these gaps with example
digests, copied preflight authority or an automatically generated approval.

## Evidence already established

[Exacly PR #117](https://github.com/whiteredhouse/exacly/pull/117) merged as
`7e17a72d13cd4fcc5caeab37e3601cdb104ee01f`. Its tree exactly matches reviewed native
source `2331d84b1b29832b3c91f291a5daef765b4c0c7d`. Full core CI passed with 4,765
tests passed and 16 skipped; the skips do not establish live merge acceptance.

The owner-approved [live preflight run 41469016096](https://github.com/whiteredhouse/exacly-delivery-acceptance/actions/runs/41469016096)
used workflow source `704d930c9f40701e6913a7de93bb2f1c97ea335e`, attempt 1, and the
reviewed native source. It verified the real merger App `5572362`, installation
`177653055`, single-repository scope and configured branch protection. Native
checks accepted the observed `admin:false`, `maintain:false`, `push:false` roles.
The run made six reads and zero writes. Its official token action logged token
revocation; its three advisory files and their digests were independently checked.

That evidence establishes read-only credential/protection compatibility. The
candidate deliberately has no `identity_approval_digest`; its independent mint
approval, PR readiness and merge-authority claims are false. The revoked token
cannot be used for this trial. The diagnostic environment approval applied only
to that exact read-only run.

## 1. Prepare the fixed data-only PR

The new `create-canary` mode runs from reviewed source on
`codex/native-merge-trial`, using the registered `app-bootstrap.yml` workflow. It
uses ordinary `GITHUB_TOKEN` authority with Contents write, Pull requests write
and Actions read for complete bounded author-run history. It receives no App key
and writes no required verification check.

The fixed candidate is:

| Field | Selected value |
| --- | --- |
| Base | `refs/heads/main` at `723cb8f3a77d4208cb5840e750cca4b9c3c0c7c8` |
| Head branch | `canary/native-merge-001` |
| Changed path | `canary.txt` only |
| Exact file contents | `canary=native-merge-001` followed by one LF |

The candidate commit's parent is the selected main commit, not the workflow's
source commit. Preparation permits four API mutation calls: create the immutable
tree, create the immutable commit, create the fixed head ref and create the PR.
The tree request can also create its content blob internally; this is a call
ceiling, not a claim that only four provider objects can exist. Retain the actual
returned identities. Existing or uncertain provider
effects require discovery and review, not a replacement branch or an automatic
new PR. No force push, branch-protection change or merge is part of preparation.

The repository must allow Actions to create PRs using `GITHUB_TOKEN`. Verify the
actual result; do not infer the setting from repository access. Confirm the PR
author and latest pusher are the intended GitHub Actions identity so that
`p1c2u` can supply an independent review. A PR authored by `p1c2u` through the
current connection cannot acquire that same user's independent author review.

Actions-created PRs may not trigger ordinary PR workflows automatically. The
separate trusted verifier below remains necessary. Record the actual PR number,
head `H`, provider-generated merge commit `M`, merge tree and ordered parents
`[B,H]` after creation. Freeze this tuple; a source change requires a new decision.

### Complete the existing branch's PR after the first refusal

[Author run 41473383834](https://github.com/whiteredhouse/exacly-delivery-acceptance/actions/runs/41473383834),
attempt 1 at source `860221a3aa537b415b6411f45c8755fb99fb11e8`, created the exact
tree, commit and branch, then received a rejected PR response. Its four mutation
attempts remain spent. Read-only reconciliation found exact head
`7e5f04446bd7eb2bd69132f27e8d20c9a967a156` and no matching PR in any state.
The original result did not retain HTTP status, so the rejection's cause is
unconfirmed. The repository's Actions PR-creation setting needs owner inspection;
the current connection cannot read that administration setting.

The supplemental `finish-canary-pr` mode selects decision
`canary-native-merge-001-finish-pr-v1` and permits one additional PR-only API
attempt. Its job receives Contents read, Pull requests write and Actions read.
It verifies the exact original failed run and retained artifact
`13155927139` with archive digest
`sha256:84cb592a85459ed660fed8694d460ab249eafa32f7a057c60b23875cf8d2da1c`,
complete bounded author/completion history, current base/head and the full
expected tree/commit before any PR creation. It cannot recreate Git objects,
update/create a ref or repeat an earlier completion attempt. Existing exact PR
discovery is read-only. Original four attempts and this supplemental ceiling of
one remain separately recorded; this is preparation authority only.

If disabled, enable **Settings → Actions → General → Workflow permissions →
Allow GitHub Actions to create and approve pull requests**. Keep the default
workflow token permissions read-only. The helper never submits a review.

## 2. Obtain genuine current verification and review

Use the existing `verify` mode from `main`, with the actual decimal PR number.
This selects the main-only `canary-verifier` environment and verifier App
`5572341`, installation `177653019`. Read back its exact main-only branch rule.
Required environment reviewers are optional in the existing setup; if configured,
the owner must approve that actual frozen run. Record the actual controls and do
not invent an approval record for an environment without that gate. The fixed
producer checks the data-only candidate against trusted
main source, runs its actual seven business cases and rechecks provider identities
before publishing at most one `exacly-generated-merge` result on exact `M`.

Read back the real check's producing App, commit, status and conclusion. Require
literal success from App `5572341` on selected `M`. Ordinary `canary-tests` has a
different producer and is not a substitute or a second required head-only check.
Do not copy a head result onto `M` or publish an arbitrary successful check.

`p1c2u` must review the real PR independently after its latest reviewable push.
Retain the actual approval and current GitHub review decision. Existing classic
protection must continue requiring strict `exacly-generated-merge` from App
`5572341`, one independent approval, last-push approval, stale-review dismissal,
administrator enforcement and no bypass or force/deletion permissions. Empty
effective rules and the exact reviewed protection digest must be rechecked.

PR approval and passing checks establish necessary merge preconditions. They do
not approve a later token, installed native configuration or delivery operation.

## 3. Select execution storage and its retention boundary

Select a trusted Linux execution context with a stable runtime and private
storage outside Git working trees. Storage initialization must pass the native
ownership checks: a mode-0700 parent owned by the executing user, safe real
ancestors, and private regular journal/key files. The marker key is a distinct
delivery key.

Initialize the key and journal with the installed native `exacly delivery
key-init` and `exacly delivery init` commands, without invoking an effect. Retain
the actual key identity, journal UUID, canonical paths, objective and original
goal. Native `delivery_store.opened()` checks the journal's device and inode as
well as its canonical path. The invocation fence binds those identities too.

A single continuously alive GitHub-hosted job preserves these identities while
its original filesystem exists. It can exercise the positive merge, immediate
offline replay and a separately approved read-only observer within that lifetime.
This requires the exact post-mint approval and effect boundaries below; merely
keeping a job alive grants no authority.

That hosted case does not establish retention or recovery after job/VM loss.
Copying a journal into an Actions artifact does not make that copy a usable
recovery journal, even when restored to the same pathname. Its safe archive is
useful retained evidence. Full recovery acceptance requires the original
persistent coordination domain, such as an owner-controlled Linux host or
self-hosted runner with the same disk and private installation, or an explicitly
reviewed migration contract. There is no implicit runtime or journal migration.

For full recovery acceptance, keep the original domain available for uncertain
outcomes, withdrawal, read-only recovery and historical inspection. Record the
chosen hosted-job or persistent-host boundary explicitly; do not promote evidence
from the narrower case into a claim about runner-loss recovery.

Decide the host/storage owner, access method, retention period, exact installed
runtime and protected evidence location before requesting runtime approval.
Credentials and key bytes stay in private storage; never put them in chat,
candidate content, approval JSON, public logs or public artifacts.

## 4. Review a fresh token-bound runtime packet

Mint a fresh merger App token for exactly this repository and the five supported
permissions: Contents write; Administration, Checks, Metadata and Pull requests
read. Retain an actual mint response or explicitly trusted, reviewed mint-run
attestation. Preserve the provenance distinction between requested permissions,
observed installation output and provider facts. A local use window is not a
claim about GitHub's actual token expiry.

The installed actor binds the actual token digest, App, installation, repository,
five permissions, mint provenance and positive UTC local window of at most one
hour. Its `identity_approval_digest` must identify independently reviewed identity
content. A matching digest or supplied permission object cannot approve itself.

The complete delivery approval pins the actual configuration and installed
runtime. It therefore cannot be approved as exact content before the token and
configuration exist. Keep the token alive in the same private trusted execution
context while the owner reviews the resulting safe packet and independently
selects its exact approval issuer, identity and content digest. An environment
approval before minting, or the consumed diagnostic approval, cannot fill this
step. Do not silently mint another token after review.

A separately authenticated approval relay could implement this boundary, but no
such native effect automation is supplied by `create-canary`. A helper must not
generate its own identity approval and operation pin and immediately apply them.
Any relay requires its own reviewed source, finite read/wait limits, actual
reviewer authentication and fail-closed handling of expiry or changed content.

The packet must contain the actual selected PR and `B/H/M/tree`; protected refs
and absent operation-marker identity; exact protection, check/App and review
facts; protected model/criteria/binding/observer blob inventories; original
objective and goal; journal/key identities; installed runtime/configuration;
policy; canonical request and native payload; operation key; approval content
and external pin; UTC expiry; effect/recovery limits; and private evidence owner.
Do not describe the packet as complete while any identity or decision is pending.

## 5. Bound one native merge and recovery

The proposed initial-positive ceiling is one logical merge, with no publication,
deployment, rollback, review dismissal or protection changes. Review actual
limits alongside the concrete packet:

| Capacity | Ceiling |
| --- | --- |
| Aggregate logical operations | 1 |
| Aggregate wall time | 360,000 ms |
| Aggregate reads | 192 |
| Aggregate rollbacks | 0 |
| Inspect / invoke / reconcile wall time, each | 120,000 ms |
| Inspect / invoke / reconcile read calls, each | 64 |
| Inspect / reconcile writes | 0 |
| Invoke writes | 2 |

Preparation reserves the single logical invocation. Inspection and any
discover-only reconciliation additionally spend their full wall/read slots.
These ceilings cover one inspect, one invoke and one reconciliation after
uncertainty; they do not authorize a second merge. Bootstrap, verifier, author and
any approval-relay operations need their own explicitly bounded accounting.

Use the installed `exacly delivery merge` command for a local preview first. The
default preview makes no provider call and establishes no live readiness.
Execution additionally requires the real approval file plus independently
selected `--approved-approval-digest`, `--issuer`, `--approval-id` and `--apply`.
The engine performs its own current inspection and retains reservation before
releasing native activity.

The native invocation can prepare one signed immutable tag object, then issue
one GraphQL `updateRefs` transaction for exact `B → M`, an `H → H` head lease and
creation of the absent signed marker ref. No ordinary head-only merge API or
fallback is permitted. The transaction leases refs; its check-policy semantics
remain those of the reviewed provider policy, not an atomic literal-success
guarantee supplied by earlier reads.

An applied result requires the exact resulting commit, authenticated marker and
GitHub's actual merged-PR identity, including the selected tree and parents.
Transport success alone is insufficient. After any possible write, a missing
marker, lost reply or generic error permits discovery only. Retain uncertainty,
spent capacity and the original resource conflict; do not retry the transaction,
reset the objective or create a new journal to obtain another effect slot.

Use `exacly delivery reconcile` with current separately pinned read authority
for discovery. An expired/replaced credential requires a distinct
`delivery-read-recovery` approval over the original intent/request/payload,
journal/goal/capacity, old and new configuration and unchanged operation profile.
That grant has zero provider writes. Exact terminal replay and `delivery show`
use retained history before credentials are loaded; they are not fresh provider
observations.

## 6. Retain acceptance evidence without overstating the result

Retain the native request/payload/approval, original external pins, journal/key
identities, reservations, native proof, exact remote refs/PR/commit facts and
terminal receipt in the selected private domain. Verify offline replay without
provider access. A later fresh acceptance observation needs its own approved
one-call zero-write packet and create-only output bundle; it reads original
history without charging or changing the original effect budget.

The native opt-in test is
`python/tests/test_automatic_merge_live.py::test_live_github_exact_merge_with_original_authority_and_authenticated_marker`.
Its independently selected inputs are `EXACLY_DELIVERY_MERGE_LIVE_PROOF` and
`EXACLY_DELIVERY_MERGE_LIVE_PROOF_DIGEST`. Do not configure a fixture as live
proof or call an unconfigured skip a passing observation.

The initial positive case does not complete authentic profile acceptance. The
remaining matrix includes real provider refusal with missing independent review
or required check, stale-base and changed-head/no-op lease transactions, a
genuine uncertain/lost-response boundary, discover-only recovery, offline replay
and a separately current read-only observer. Distinguish a local preflight refusal
from server enforcement. Concurrent-change controls and negative provider probes
are effects with their own exact identities and budgets, even when rejection is
expected; they are not included in the one-positive-merge ceiling above.

Keep REQ-041 proposed until its required authentic acceptance establishes the
provider guarantees. A merge receipt establishes that repository effect, not
current implementation verification, later-stage authority or runtime health.

## Native contract references

The reviewed implementation is [Exacly source `2331d84`](https://github.com/whiteredhouse/exacly/tree/2331d84b1b29832b3c91f291a5daef765b4c0c7d).
Its authoritative contracts are:

- `docs/product-delivery-merge.md`: supported profile, exact approval and recovery
  semantics, operator commands and nonproduction packet requirements.
- `python/src/exacly/automatic_merge.py`: closed configuration, policy and payload
  schemas; actual actor/time checks; protected inventories; signed marker and
  three-ref transaction construction.
- `python/src/exacly/delivery_automation.py`: request/approval schemas and external
  `ApprovalPin` content-selection contract.
- `python/src/exacly/delivery_store.py` and `delivery_runtime.py`: original journal
  identity, conservative accounting, uncertainty and invocation ownership.
- `python/src/exacly/delivery_engine.py`: local preview, approved apply, historical
  replay and read-only reconciliation.
- `python/src/exacly/github_merge.py`: fixed provider transport and actual native
  inspect/invoke/reconcile protocol.
- `python/src/exacly/automatic_merge_live.py`: separately pinned one-call live
  acceptance observer; `delivery_io.py` and `cli.py`: fixed CLI bootstrap.
