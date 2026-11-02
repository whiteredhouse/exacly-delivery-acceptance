# Exacly merge acceptance canary

A small public repository for a bounded, independently approved GitHub merge trial.
Its application computes invoice totals in integer cents. It has no external
dependencies, network client, credentials, publishing or deployment code.

Run its deterministic checks with the Python standard library:

```sh
python3 -B -m unittest discover -s tests -v
```

`canary-tests` is the only ordinary CI check. It runs for every pull request and
push to `main`, has a five-minute deadline and receives only `contents: read`.
Checkout is pinned and does not persist credentials. This ordinary job receives
no App credentials. There are no tag triggers, application deployments, automatic
mergers or privileged pull-request triggers. The separate manual App workflow
below can create genuine verification metadata or collect advisory credential
evidence under its narrowly scoped App.

## Ordinary CI and the generated merge commit

On a `pull_request` event, the checkout normally tests GitHub's generated merge
commit M, but the GitHub Actions check run is attached to PR head H. Logging the
checked-out revision does not change that attachment or establish independent
evidence for M.

The current Exacly merge profile requires its selected check runs on exact M.
This ordinary CI workflow alone therefore does not make the repository compatible.
The local read-only verifier below checks one narrowly bounded candidate against
independently pinned trusted source. A separately approved producer App must still
establish fresh GitHub identities and publish its actual verification result on M.
The manual workflow below implements that bounded producer. Its source and
controlled tests do not establish authenticated App access or live merge acceptance.
Do not copy a head result to M, create an arbitrary successful check, or allow
candidate changes to approve their own verification meaning.

## Native merge trial preparation

The branch-only `create-canary` mode prepares one fixed data-only PR from the
reviewed main commit. It changes only `canary.txt` to `canary=native-merge-001`.
The workflow uses its ordinary `GITHUB_TOKEN` to publish the Git objects, create
`canary/native-merge-001` and open the PR as `github-actions[bot]`. This separates
the PR author from the human reviewer `p1c2u`. It receives no App key, cannot
publish the required App check and performs no merge or protection change.

This mode runs only from `codex/native-merge-trial`, with an empty PR input and
the first workflow attempt. It never overwrites the fixed branch or retries an
uncertain write. A later run may discover an existing exact PR but cannot use a
new run or output path to reset a previous attempt's write allowance. Its sole
artifact is `author-result.json`; the default repository token permissions stay
read-only, with write permissions limited to this job.

The first author run created the exact branch and reached a rejected PR request.
The separately reviewed `finish-canary-pr` mode permits one additional PR-only
attempt for that existing branch. It pins the original run and retained result,
rechecks the full branch/tree/commit and complete run history, and receives only
Contents read, Pull requests write and Actions read. Its supplemental limit is
one PR call, recorded alongside the original four attempts. It cannot repeat
source/ref writes, reset the original allowance or retry a previous completion
attempt. An existing exact PR can be discovered without writes.

PRs created with `GITHUB_TOKEN` do not trigger ordinary PR workflows. The
existing main-only `verify` mode must therefore be dispatched explicitly for
the created PR. The genuine verifier App then runs the fixed tests and publishes
its check on exact M; the human supplies an actual independent review.

[The native trial runbook](docs/NATIVE-MERGE-TRIAL.md) describes the remaining
runtime approval and persistent-host requirements. PR preparation and successful
preflight do not grant native merge authority.

## Trusted manual App workflow

[The account setup guide](docs/APP-SETUP.md) describes the selected App identities,
classic protection and exact main-only environment restrictions. Publish and
review all source first, apply and read back those guards, then store each key
only in its own protected environment. App registration and a matching ID are
not an authenticated preflight or an Exacly runtime grant.

`Trusted App bootstrap` runs only by manual dispatch. Its main-only `preflight`
mode checks each one-repository role and observes actual endpoint access. Its
main-only `verify` mode uses only the verifier App to check
one selected same-repository PR whose sole change is the bounded `canary.txt`
label. Candidate Git objects are data; the App token never enters Git, verifier
or business-test subprocess environments.

The fixed helper validates current B/H/M/tree and the protected trusted source,
runs the local verifier's seven actual business cases, then rechecks GitHub
identities before creating at most one `exacly-generated-merge` check on exact M.
Only the genuine verifier App's result can satisfy the configured required check.
The main merger preflight attempts its legacy scope, role and protection checks;
it performs no merge, source/ref update, PR creation, review dismissal or policy change.

The separately owner-reviewed `codex/preflight-diagnostics` branch has two
additional modes. `diagnose-merger` reproduces the unchanged original helper's
rejection of the App token's observed `push: false` flag. `app-grant-preflight`
uses pinned native Exacly from [PR #117](https://github.com/whiteredhouse/exacly/pull/117)
to validate an advisory token-bound App-grant candidate and read actual server
protection. It reports no independent mint approval, PR readiness or merge
authority. Both modes require explicit key release through the separate,
owner-reviewed `canary-merger-diagnostic` environment and approval of the exact
frozen run; they do not need to merge into main. See the
[branch preflight setup](docs/APP-SETUP.md#7-owner-reviewed-app-grant-candidate-preflight).

The hosted verification path checks its real run and complete bounded workflow
history. Reruns and prior unsuccessful verification for the same PR block a new
check write; a unique exact existing result may be discovered read-only. A new
output path or replacement PR does not resolve an earlier unknown effect. The
Checks API has no global conditional-create guarantee: no automatic POST retry,
global exactly-once claim or implicit uncertainty reset is made here.

GNU timeout and the job deadline bound the hosted invocation. Private runner
output is temporary, and no raw evidence directory or credential is uploaded.
Only `app-grant-preflight` selects three safe advisory metadata files for
seven-day artifact retention. The pinned action attempts token revocation during
post-job cleanup; verify its actual result. The candidate is not an installed
configuration and cannot supply approval or a token for a later job.
Select protected durable retention separately before a live merge trial. A
successful check remains verification metadata; actual independent review,
current native readiness and the separately approved finite merge packet are
still required. No App keys have to be sent through chat or committed here.

## Read-only generated-merge verifier

`tools/verify_merge.py` is a fixed local verifier for one canary data change. Run
the independently reviewed trusted source copy with isolated Python, separately
from the candidate Git object repository:

```sh
python3 -I -B /trusted/source/tools/verify_merge.py \
  --repository /trial/candidate \
  --manifest /trusted/packets/base-manifest.json \
  --manifest-sha256 sha256:INDEPENDENTLY_SELECTED_DIGEST \
  --base-ref refs/heads/main --head-ref refs/heads/canary/positive \
  --base BASE_SHA --head HEAD_SHA --merge MERGE_SHA --tree MERGE_TREE_SHA
```

These uppercase values are placeholders, not authority or preselected identities.
The operator must independently select the exact B/H/M/tree and manifest pin.
The manifest must be outside the candidate repository, and the trusted source and
candidate repository must be separate, non-nested directories. Its closed schema is:

```json
{
  "kind": "exacly-canary-trusted-base",
  "schema_version": "1",
  "base_ref": "refs/heads/main",
  "base_revision": "EXACT_REVIEWED_BASE_SHA",
  "files": {
    "EVERY_BASE_FILE_PATH": {
      "mode": "100644",
      "blob": "EXACT_GIT_BLOB_SHA",
      "sha256": "sha256:EXACT_FILE_BYTES_DIGEST"
    }
  }
}
```

The inventory covers the entire reviewed base tree, including the app, all test
files, tools, workflows, configuration, README and baseline canary. The pin hashes the actual
manifest bytes. A candidate-supplied manifest or self-selected pin is insufficient.

The verifier:

- Reads local Git objects without fetching, checking out or running candidate
  code. Replacement objects, lazy fetching, optional locks, hooks and all network
  protocols are disabled for its fixed Git commands.
- Verifies current local B/H refs, exact object bytes, selected M/tree and ordered
  parents `[B,H]`. Local facts do not prove current remote GitHub facts.
- Compares the complete base inventory against the external manifest, checks the
  actual trusted source bytes against it, and requires H and M to preserve every
  file, mode and byte except `canary.txt`. Links, submodules, executable modes,
  missing and unexpected files are rejected.
- Accepts only a different, matching H/M canary consisting of one ASCII line:
  `canary=LABEL`, followed by a newline. LABEL starts with a lowercase letter and
  contains at most 32 lowercase letters, digits or hyphens. It is inert text;
  no command, path, criteria, test or policy is selected by that label.
- Captures the verified trusted app and business-test source bytes, then runs its
  seven actual cases in a fresh fixed `python -I -B` child
  with a credential-free environment and exact case names. No candidate module
  path, test discovery, cached bytecode or generated tests enter that child.
  All seven cases must pass without skips or expected failures.
- Rereads the local B/H refs before returning, and emits an unsigned JSON report
  naming M/tree/parents, measured source hashes, canary delta and actual test
  output. This reports that trusted tests ran and candidate code is byte-identical;
  it does not claim arbitrary candidate code was executed or independently approved.

The finite bounds are 64 files, 128 KiB per source/blob, 96 fixed Git reads,
three seconds per Git call, five seconds for trusted tests and a 256 KiB combined
process-output ceiling. A cooperative 20-second work deadline is checked between
operations; child termination/reaping can add up to two seconds. File reads,
source inventory and process startup are not controlled by an external watchdog
in this tool. A caller needing a strict end-to-end deadline must supply its own
trusted watchdog. Only Git metadata and interpreter cache directories are ignored
in the trusted source; the fixed byte runner does not load those caches. No
repository files or provider state are written. The caller can retain stdout in
its separately approved location.

The ordinary `canary-tests` job also runs positive and negative verifier fixtures
against real local Git commits: wrong refs/parents/tree, protected-file and mode
changes, unexpected files/links/submodules, malformed canary data, manifest drift
and trusted-source drift. These controlled tests are not authentic GitHub acceptance.

## Protection and approval setup

The current `github-atomic-merge-v1` profile expects readable classic branch
protection and an empty effective ruleset list. Its policy requires strict,
App-pinned required checks, at least one independent approving review,
last-push approval and administrator enforcement. It excludes review bypass
actors, forced updates, deletion, mandatory linear history, signed-commit
requirements and merge queues. Repository creation alone does not establish
any of these settings.

Freeze the actual required check name and producer App ID from the selected
trusted verifier. An operator must apply and independently review the exact
protection and actor configuration before the trial. Do not weaken protection,
dismiss a blocking review, substitute a different merge API or add an approval
exception just to obtain a successful result.

## Canary operations

Prepare exact, independently reviewed PRs and finite operations for:

1. One authorized positive merge changing only the bounded label in `canary.txt`,
   with exact base B, head H, generated merge M and tree recorded. Application,
   test, workflow, verifier and documentation changes are outside this verifier.
2. Rejection after the selected head or base changes, including an actual
   concurrent head-lease rejection. Verify that rejected provider transactions
   neither move the base nor create their marker.
3. Rejection when required checks or independent reviews are missing. A local
   preflight refusal alone does not prove GitHub's enforcement.
4. An uncertain-response recovery that discovers the actual effect without
   resending a mutation, followed by exact historical replay offline.
5. A separately authorized read-only observation of the retained positive merge.

The supported marker namespace is
`refs/tags/exacly-delivery-operations/<operation-hash>`. No release tag or other
destination is implied. Actual GraphQL ref-transaction event delivery and PR
recognition must be established by authentic acceptance, not inferred from this
source scaffold or controlled tests.

Store the exact requests, approvals, original-goal journal and finite budgets,
key descriptors, receipts, rejections and recovery evidence in the approved
private retention location. Do not commit tokens, private keys or approval
documents to this public repository. A fixture issuer name, matching content
digest or successful CI run is not independent human approval.

The application and local verifier perform no provider writes. The manual App
helper can produce only the scoped verification check described above; it grants
no merge authority. Source verification and authentic operational acceptance
remain separate. The original Exacly product model's lifecycle and observed state
are not changed by these files.
