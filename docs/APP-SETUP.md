# Trusted Apps and exact generated-merge verification

This setup concerns only the public repository
`whiteredhouse/exacly-delivery-acceptance`, ID `1442278205`. Its two selected Apps are:

| Role | App ID | Installation ID | Environment and secret |
| --- | --- | --- | --- |
| Verifier | `5572341` | `177653019` | `canary-verifier` / `VERIFIER_PRIVATE_KEY` |
| Merger | `5572362` | `177653055` | `canary-merger` / `MERGER_PRIVATE_KEY` |

These are selected identities in `config/apps.json`. Actual installation scope,
permissions and endpoint access still require authenticated preflight. Registering
an App, installing it or adding its key does not create Exacly runtime authority.

The manual workflow uses trusted main source and the fixed helper
`tools/app_bootstrap.py`. It has two modes: read-only role preflight and genuine
`exacly-generated-merge` check production for one narrowly bounded canary PR.
Its source implementation and controlled tests are separate from actual hosted
execution, successful provider readback and authentic merge acceptance. Do not
claim those later steps from the presence of these files.

## 1. Publish the reviewed credential-free source first

Have the workflow, helper, fixed verifier, tests and configuration independently
reviewed and merged to this new repository's main before applying its classic
protection. Retain the actual resulting commit and complete file inventory.
Applying the required M check before its trusted producer source exists would
block that bootstrap. No App key is needed for this source step.

The existing ordinary `canary-tests` CI remains one read-only job. Its PR check
is attached to H even when checkout tests generated merge M. It is additional
evidence, not a substitute for the independent producer's actual check on M.

Do not add keys while the new main is unprotected or while either environment
allows candidate branches. A workflow's main-ref condition alone is insufficient:
candidate workflow source could change that condition.

## 2. Apply and read back classic protection

An authorized administrator reviews and applies `config/protection.json` only
to this repository's main. Neither runtime App has Administration write.
Using the administrator's own authorized CLI session from the reviewed source:

```sh
gh api --method PUT \
  repos/whiteredhouse/exacly-delivery-acceptance/branches/main/protection \
  --input config/protection.json
```

Read back the actual policy, separate required-signatures endpoint and effective
branch rules. Confirm all of the following before storing keys:

- Strict required check `exacly-generated-merge`, produced by App `5572341`.
  The payload has an empty legacy `contexts` list and its explicit App-pinned
  `checks` entry. Ordinary `canary-tests` is not a second required H-only context.
- One independent approving review, stale-review dismissal, latest-push approval,
  administrator enforcement and conversation resolution; no review bypass actors.
- No force updates, deletion, required linear history or required signatures.
- Effective branch rules are exactly `[]`; no merge queue or inherited ruleset.

Do not disable an organization rule, weaken this policy, invent a successful
check or bypass protection to proceed. A failed or unavailable readback leaves
setup blocked.

## 3. Create two environments with exact main-only branch rules

In this repository's **Settings → Environments**, create `canary-verifier` and
`canary-merger`. For each environment:

1. Choose **Selected branches and tags** under deployment branch/tag restrictions.
2. Add exactly one **Branch** rule named `main`. Add no tag rule, wildcard or
   other branch. Do not choose all branches or the broader protected-branches option.
3. Read back the environment and its complete branch-policy list using an authorized
   account or the Settings UI. The API field `deployment_branch_policy` must be
   `{"protected_branches": false, "custom_branch_policies": true}`. The complete
   policy list must contain exactly one rule with `type: branch` and `name: main`.
4. Retain that readback together with the classic-protection readback. Have its
   meaning independently checked before making either key available.

Required environment reviewers are an optional additional control, not a
replacement for the independent PR review. If selected, configure and verify
that rule before the key. Review the prevention-of-self-review setting against
the actual available reviewers; do not silently require a second environment
approver when the same sole operator must trigger the run.

The workflow names each environment explicitly and sets `deployment: false`.
The environment supplies its server-side secret gate; the workflow is not an
application deployment. No source branch, workflow input or candidate file can
choose another environment or secret name.

## 4. Store each key in its own environment

Only after both main protection and both exact main-only environment restrictions
have been verified, use the GitHub Settings UI to add:

- `VERIFIER_PRIVATE_KEY` only in the `canary-verifier` environment.
- `MERGER_PRIVATE_KEY` only in the `canary-merger` environment.

Use each App's corresponding private key. Do not paste key or installation-token
bytes into chat, issues, public files or logs. Do not create repository-wide or
organization-wide copies of these secrets; ordinary candidate PR workflows must
not receive them. Keep private key storage and rotation with the selected owner.

The workflow passes a private key only to pinned official
`actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510`
(`v3.3.0`). Its immutable action definition accepts numeric `app-id` as well as
the preferred client ID. The numeric input is used because the selected App IDs
are known. Owner and repository are fixed, token permissions are explicitly
reduced to the role below, and automatic post-job token revocation remains on.

| Token permission | Verifier | Merger |
| --- | --- | --- |
| Contents | Read | Write |
| Checks | Write | Read |
| Pull requests | Read | Read |
| Administration | None | Read |
| Metadata | Read | Read |

Token minting and revocation are credential operations. The preflight helpers
perform provider reads only; a write-capable token does not authorize an effect.
The merger job invokes no Exacly merge, ref mutation, PR creation or review action.

## 5. Run manual authenticated preflight

Open **Actions → Trusted App bootstrap → Run workflow**, select `main` and mode
`preflight`; leave the PR number empty. Both role jobs use their separate
environments. They run with an ordinary `GITHUB_TOKEN` limited to Contents read.

The fixed helpers must establish the real token scope, expected installation
identity and role-specific endpoint access. The official action's actual
`installation-id` output is passed to the helper and compared with the selected
configuration; no supplied JSON can substitute an invented authenticated identity.
Keep permission, protection, signatures, required-check or actor-fact mismatches
blocked. For the merger, actual `admin=false`, `maintain=false`, `push=true`
and one-repository scope must be observed rather than inferred from permission names.

Do not interpret a skipped job, transport success, unknown result or absent proof
as a successful preflight. Preflight does not merge, publish a package, deploy,
post a check or satisfy the genuine positive merge-observation case.

## 6. Produce a genuine exact-M check for a selected canary

After source, guards and preflight are established, independently select an open
same-repository PR whose only change is the bounded label in `canary.txt`.
Run the same workflow from `main`, mode `verify`, with its positive decimal PR
number. The input is data passed through an environment variable and a quoted
helper argument; it cannot select shell code, a source checkout or an endpoint.
The canonical run title is `canary-bootstrap:verify:pr-N`, where N is that exact
decimal PR number; preflight runs use `canary-bootstrap:preflight:pr-0`.

The helper must authenticate the actual repository and B/H/M/tree/parents, use
the exact protected workflow commit as trusted source and independently select
its complete manifest. It runs the fixed local verifier with captured trusted
business-test bytes. Candidate Git data is never checked out, imported or executed.
It rechecks current provider identities and publishes its actual result under
the verifier App on exact M, then reads the created check back. A failing,
uncertain or missing verification is never relabelled as success. A changed
main or PR tuple requires a new applicable evaluation.

Before any new check POST, the helper authenticates its actual hosted run using
the ordinary job token's Actions read permission. It checks the real run ID,
attempt, workflow path, manual event, main branch, source commit and canonical
PR title against the protected workflow context. It also requires a complete,
bounded run history for this workflow/main and the same PR. Missing or incomplete
history refuses publication; it is not proof that no earlier effect occurred.

A rerun attempt greater than one, or an earlier failed, cancelled, timed-out or
still-running verification for that PR, blocks a new POST. This deliberately
includes failures that may have occurred before a write: the temporary runner
cannot prove otherwise. A unique, authenticated, matching check already owned by
the verifier App on current M can instead be freshly verified and reconciled
read-only, without another POST. An unknown result needs that read-only
reconciliation and operator review. A new output directory, a fresh workflow
dispatch or a replacement PR cannot be used to erase uncertain history or reset
the original approved trial's accounting.

Each helper call runs under GNU `timeout` with a 120-second work limit and a
five-second kill-after interval; each job has a five-minute platform limit.
Runs serialize per mode/PR and are not cancelled by a newer dispatch. The
private output directory is new, absolute and outside the checkout. The helper
receives its installation token only through `CANARY_APP_TOKEN`. Only the verify
job adds Actions read to the ordinary Contents-read token and passes it through
the separate `CANARY_ACTIONS_READ_TOKEN` variable for hosted-run history reads.
Neither App gains an additional permission, and candidate Git and test subprocesses
receive neither token. No raw output directory, key,
token or credential-bearing error is uploaded as an Actions artifact. Safe
receipt/status summaries may appear in the job log. Select protected durable
retention separately before any live merge trial; runner-local output is temporary.
Concurrency serializes hosted dispatches for the same mode/PR and does not cancel
an older writer. The history guard is conservative hosted-run evidence, not a
generic durable ledger, atomic cross-provider transaction or exactly-once guarantee.

This check is verification metadata. It grants no merge, review, publication,
deployment, rollback or Exacly runtime delegation. Exact required-check App/SHA,
current reviews, PR CLEAN state and the complete independently approved finite
trial packet remain separate prerequisites. Do not retry an uncertain provider
effect blindly or treat a fixture result as authentic acceptance.

## Primary source references

- [Pinned token action inputs, outputs and automatic revocation](https://github.com/actions/create-github-app-token/blob/64ab729a6294000f5aa4a4bc0b73d1f32bc45510/action.yml).
- [Pinned token action permission and repository scoping documentation](https://github.com/actions/create-github-app-token/blob/64ab729a6294000f5aa4a4bc0b73d1f32bc45510/README.md).
- [Environment branch/tag restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments#deployment-branches-and-tags).
