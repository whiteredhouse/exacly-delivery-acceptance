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
Checkout is pinned and does not persist credentials. There are no tag triggers,
deployment workflows, automatic mergers, privileged pull-request triggers or
write-capable jobs in this scaffold.

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
This repository contains no check-publishing code or write-capable verification
workflow. Do not copy a head result to M, create an arbitrary successful check, or
allow candidate changes to approve their own verification meaning.

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

The inventory covers the entire reviewed base tree, including the app, both test
files, verifier, workflow, README and baseline canary. The pin hashes the actual
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

This scaffold performs no provider writes and grants no merge authority. Source
verification and authentic operational acceptance remain separate. The original
Exacly product model's lifecycle and observed state are not changed by these files.
