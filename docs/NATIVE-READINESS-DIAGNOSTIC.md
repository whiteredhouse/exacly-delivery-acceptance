# Read-only native readiness diagnostic

The native diagnostic runtime is pinned to
`6e210d337f11cbd0e48fdb9df15d4d5089ce5782`. The existing native trial and
App-grant preflight retain their original runtime pins.

The first native positive trial accepted the owner's exact selection but stopped
at the native read-only readiness check. Its retained report has no applied
receipt, and the original hosted runner's private journal and key are gone.
The exact failure condition was hidden by a generic error.

The first [read-only diagnostic](https://github.com/whiteredhouse/exacly-delivery-acceptance/actions/runs/41560965600)
reached final fact validation after 18 read attempts and returned
`ready_facts / validation_failed`. A versioned REST comparison showed
that GitHub's `2026-03-10` API removes `merge_commit_sha`, which the old adapter
read as `None`. The updated runtime obtains the pending candidate through
GraphQL `potentialMergeCommit` and the completed merge through `mergeCommit`.
It preserves exact repository, PR, revision, tree, parent, protection and marker
checks. The diagnostic fixture now omits the removed REST field too.
See GitHub's [REST breaking changes](https://docs.github.com/en/rest/about-the-rest-api/breaking-changes)
and [GraphQL pull-request fields](https://docs.github.com/en/graphql/reference/pulls).

This API incompatibility is reproducible. The failed App job did not retain its
raw response, so the version comparison does not establish that it was the only
blocked condition in that session. New fixed readiness-check identifiers expose
the individual rejected rule without publishing response data or exception text.
They identify a check, such as `review_decision`, and do not invent the missing or
rejected value. Unknown diagnostic codes remain hashed instead of echoed.

`native-readiness-diagnostic` is a separate manual job on
`codex/preflight-diagnostics`. It calls the reviewed native
`GitHubMergeAdapter.inspect` once for the same fixed PR #5, base, head, generated
merge commit, protected files and branch policy. It does not call the delivery
engine, initialize a journal, spend or reset a delivery goal, construct a delivery
approval, invoke a merge, reconcile the original operation, or run an observer.
The consumed first native trial remains stopped.

The required reviewer for `canary-merger-diagnostic` must approve the actual
immutable run before its App key becomes available. A successful environment
review allows this diagnostic source to mint its selected one-repository App
token and perform read-only inspection. It supplies no native merge authority.
The assistant must never approve the environment on the owner's behalf.

The App token uses the native profile's exact six permissions, including
`contents:write`. The selected native `inspect` call has a zero-write ceiling.
A second independent HTTP allowlist permits only fixed GET endpoints and the
two exact installed GraphQL read queries with fixed variables. It refuses any
mutation before network dispatch, limits work to 120 seconds and 64 attempted
reads, and refuses redirects and repeated requests. The profile's inactive
`invoke` configuration still requires its normal write ceiling; no invoke path
is called by this job.

A fresh local diagnostic key exists only to meet the native inspection profile's
private-key prerequisite. It is not the original key, does not replace a journal,
and cannot establish why the original runner's key or storage may have failed.
The local identity pin is a proposed diagnostic identity marked unapproved.
There is no independently approved actor installation or selected delivery
approval. Mint metadata records reviewed action inputs and the actual installation
output, not a retained provider mint response or verified provider token expiry.

The job uploads exactly three private-mode JSON files for seven days:

- `mint-attestation.json` records the actual run and requested mint scope.
- `actor-candidate.json` records the unapproved exact-token candidate.
- `native-readiness-diagnostic.json` records fixed target and source pins,
  bounded endpoint labels/statuses/counts, input/result digests and the native
  advisory result. Only recognized fixed diagnostic fields may be public.

The key, raw response bodies, headers, arbitrary exception text and full native
provenance facts are never uploaded. The pinned official action revokes its token
in its post step. Inspect the actual run's cleanup evidence before treating that
revocation as observed.

A successful diagnostic describes current read-only conditions for a fresh token
and key. It does not reproduce the old App session, recover the lost journal,
prove that a future merge is ready, or authorize another native attempt. Any new
native trial needs a separately reviewed attempt protocol and fresh selection of
the actual post-mint packet.
