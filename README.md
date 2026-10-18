# Plumbline

**Engineering guardrails for small teams, with the evidence to back them.**

This first release is the contractor-access module, for AWS, Azure and GCP. Small companies give contractors and vendors cloud access, then forget to remove it. Plumbline ties every grant to a contract, expires it automatically, shows the approver what the access can reach, and later checks what the contractor actually did against what they asked for. Every finding links to the exact event behind it.

> **Status: early (v0.4).** The core logic is tested (233 tests, CI on Python 3.11 to 3.13). Scope enforcement, the orphan scan, and revocation have all been exercised on a real **AWS** account; the Azure and GCP gateways are new, correct against their documented SDK shapes and covered by unit tests with injected stand-in clients, but have **not** been run against a live Azure subscription or GCP project — see [Azure and GCP: what's the same, what's not](#azure-and-gcp-whats-the-same-whats-not). Nothing has been run against a live LLM, and the evaluation uses **simulated** data. The change-risk scorer and SLO starter kit (modules 2 and 3) are not yet used on a real deployment pipeline or real production traffic. See [What is and isn't tested](#what-is-and-isnt-tested) and [Not built yet](#not-built-yet) before relying on it.

## How it works

```mermaid
flowchart LR
    C[Contractor] -->|1. request: purpose, ticket, policy| R[Request]
    R -->|inside contract scope?| S{Scope check}
    S -->|no| X[Refused and audited]
    S -->|yes| B[Blast-radius preview]
    B --> A[Approver decides]
    A -->|approve| K[Contractor claims credentials once]
    K -->|STS session policy, expires at or before contract end| G[Grant]
    G --> T[(CloudTrail)]
    T --> V[Review: declared vs actual]
    I[(IAM principals)] --> O[Orphan scan]
    T --> U[Ungranted-activity scan]
    T --> N[Anomaly check vs the contractor's own history]
    V --> F[Findings with evidence ids]
    O --> F
    U --> F
    N --> F
    F --> E[Explanation: rules first, optional LLM, citations checked]
    R -.-> L[(Hash-chained audit log)]
    A -.-> L
    K -.-> L
    F -.-> L
```

### What each part does

| Feature | What it does |
|---|---|
| Multi-cloud | A contract names a provider (AWS, Azure or GCP). The request/decide/claim/revoke flow, scope ceiling, blast radius and anomaly detection work the same way on all three; what each one actually does to issue and revoke access is necessarily different — see [Azure and GCP: what's the same, what's not](#azure-and-gcp-whats-the-same-whats-not). |
| Contract binding | A grant never outlives its contract. Ending a contract revokes its grants and cancels open requests. |
| Scope ceiling | Each contract carries the most a contractor may ever request. Requests outside it are refused and audited. A requested `s3:*` is **not** inside a ceiling of `s3:Get*`. |
| Purpose and ticket | A request must state what the access is for and cite a ticket. |
| Separation of duties | You cannot approve your own request. |
| Blast-radius preview | Plain-language summary and risk level (low to critical), shown to the approver before they decide. |
| Time-limited sessions | Credentials come from STS with a session policy limited to what was approved. They are returned once and never stored. |
| Revocation | Per-contract IAM role, with a Deny-older-sessions policy. See limitations. |
| Orphan scan | Finds contractor principals with no contract, an unknown contract, an ended contract, or no use for 90 days. |
| Declared vs actual | Flags refused calls outside scope, sensitive calls that were allowed, and unused permissions, with a tighter suggested policy. |
| Ungranted-activity scan | Flags activity on a contract role that no grant covers (credentials used outside Plumbline, or after expiry or revocation). |
| Anomaly detection (M1.8) | Compares each session with that contractor's own earlier sessions on the same role: one session used from several addresses, volume or breadth far above their usual, new source addresses, new actions, unusual hours. Signals are weighted, and a finding needs a total of 3 (a new address alone is not enough). With at least 20 earlier sessions an optional Isolation Forest (scikit-learn) adds a second opinion. Every signal names the events behind it, and the baseline used is stored as evidence. |
| Evidence-checked explanations | Findings cannot exist without stored evidence. An optional LLM explanation is rejected unless it cites evidence that belongs to that finding. |
| Audit trail | Hash-chained log of every request, decision, grant, revoke and scan. |
| Change-risk scorer (module 2) | Scores a proposed change from facts you give it — environment, services touched, whether requester and approver are different people, review count, rollback plan and whether it was tested, size, timing, and declared change freezes — as a sum of named, weighted signals. Every score comes with the reasons behind it. |
| SLO starter kit (module 3) | Define a target (e.g. 99.9% over 30 days), record good/bad events, and get the error budget remaining plus a two-window burn-rate alert (the method from Google's SRE Workbook), so a budget that is burning too fast is flagged before it is gone. |
| SOC 2 evidence report | `GET /reports/soc2?start=..&end=..` (JSON) and `/reports/soc2.pdf` map what Plumbline recorded to SOC 2 Security criteria CC6.1, CC6.2, CC6.3, CC7.2 and CC7.3, with counts, audit-log integrity and the head hash, open high and critical findings, and a section on what the report does not cover. It is evidence for an auditor, not a statement of compliance. Criterion wording is a paraphrase, not the AICPA text. |

## Azure and GCP: what's the same, what's not

Plumbline's contract/request/decide/claim/revoke flow, scope ceiling, blast-radius preview, orphan scan and anomaly detection all work the same way on all three clouds - a contract names a `provider` ("aws", "azure" or "gcp"), and everything above the gateway layer is written against the clouds' shared shape, not AWS's specifically. What differs is how each cloud actually implements "issue time-limited access" and "take it away again", because the three clouds do not have equivalent primitives. The honest version, cloud by cloud:

| | AWS | Azure | GCP |
|---|---|---|---|
| "Issue access" primitive | STS `AssumeRole` | A time-bound RBAC role assignment (Azure AD PIM activation) | IAM Credentials `generateAccessToken` |
| What `claim()` returns | A real access key, secret and session token | **No bearer credential at all** - access follows the contractor's own Azure AD sign-in once the assignment is active | A real OAuth access token |
| Session duration | 15 min to 12 h (role's `MaxSessionDuration`) | 5 min to 24 h (Microsoft's PIM guidance) | 10 min to **1 hour** - GCP will not mint a longer-lived token directly |
| Per-request narrowing | A real inline STS session policy, enforced by AWS | **Not enforced** - Azure RBAC cannot narrow an active assignment below its role; the requested scope is recorded and approved, not technically bounded | **Not enforced**, same reason - a generated token carries the service account's full bindings |
| Revoking before expiry | A Deny policy keyed on `aws:TokenIssueTime`, ending every session on that role issued before now | Removing the role assignment; Azure re-checks RBAC per request, so this is a real revoke, modulo Microsoft's own documented propagation delay (usually under 5 minutes) | Removing the IAM policy binding so no new token can be minted; an **already-issued token keeps working until it expires** (up to the 1-hour cap) - GCP has no way to invalidate one early |
| Activity log used | CloudTrail (management events only, 90-day lookback, minutes of lag) | Azure Monitor Activity Log (control-plane only - data-plane calls need Diagnostic Settings, configured per resource) | Cloud Logging Admin Activity logs (control-plane only - Data Access logs are off by default, billed separately, and not available for every service) |
| Principal reference (`role_arn` field) | An IAM role ARN | `"<service principal object id>@<role-assignment scope>#<role definition id>"` - Azure needs all three to activate an assignment, and there's no single ARN-like id that carries them, so they're packed into one field (see `plumbline/identifiers.py`) | A service account email |

None of this is a Plumbline shortcoming to be fixed later - it is what each cloud's own IAM actually offers. A deployment that needs enforced per-request narrowing on Azure or GCP, not just an audited ask, would need to lean on each cloud's own resource-level IAM Conditions (Azure ABAC, GCP conditional bindings), which only cover specific resource types today and are out of scope here.

Setup: install the matching optional dependency group (`pip install -e .[azure]` or `.[gcp]`; see `requirements-azure.txt` / `requirements-gcp.txt`), make sure that cloud's own credentials are available the way its SDK expects (`az login` or a service principal for Azure; `GOOGLE_APPLICATION_CREDENTIALS` or Application Default Credentials for GCP), and set `PLUMBLINE_AZURE_SUBSCRIPTION_ID` and/or `PLUMBLINE_GCP_PROJECT_ID`. Azure's orphan scan additionally needs a Microsoft Graph client passed in by hand (there is no single official synchronous Graph SDK to default-construct the way boto3 is); without one, `AzureGateway.list_contractor_principals` raises a clear error naming what's missing, and the orphan scan skips just that provider rather than failing outright (the other configured clouds still get scanned - see `Analyzer.scan_orphans`).

## Try it with no AWS account (demo mode)

```bash
pip install -r requirements.txt
export PLUMBLINE_DEMO=1
export PLUMBLINE_KEYS='ka=alice@acme.example:contractor;kb=bob@corp.example:approver;kz=admin@corp.example:admin'
uvicorn plumbline.main:app
```

Open http://127.0.0.1:8000, sign in with `kb` to approve a request and `ka` to claim credentials. Demo mode uses an in-memory fake of AWS, so the credentials are fake and nothing real is touched.

## Before you point this at AWS

1. Create **one IAM role per contract**, named `contractor-<something>`, tagged `plumbline-contractor=true` and `plumbline-contract-id=<contract id>`. The trust policy lets Plumbline's role assume it (`examples/contract-role-trust.json`). Give the role at least the permissions of the contract's ceiling: the effective access is the *intersection* of the role's permissions and the session policy.
2. Give Plumbline a runtime identity with only the permissions in `examples/iam-plumbline-runtime.json`.
3. Set real API keys in `PLUMBLINE_KEYS` and put the service behind your single sign-on or a reverse proxy. The built-in API keys are a simple stand-in, not a substitute for SSO. Do not expose this to the internet as is.
4. Use a persistent database (`PLUMBLINE_DB=/path/plumbline.db`) and **save the audit head hash somewhere outside the system** (see limitations).
5. Try it in a test account first. The IAM examples have been written carefully but not validated against a live account.

Optional LLM explanations: set `ANTHROPIC_API_KEY` (and optionally `PLUMBLINE_MODEL`). Without it, deterministic template explanations are used.

## What is and isn't tested

| Area | How it is tested |
|---|---|
| Policy engine, access flow, analysis, evidence rules, audit chain, API roles | Unit and integration tests (233), across all three providers where the behaviour is provider-specific (duration bounds, action syntax, blast radius, the full request/decide/claim/revoke flow) |
| Real `Boto3Gateway` (AWS) | Against [moto](https://github.com/getmoto/moto) for STS and IAM, and a botocore Stubber for CloudTrail (including pagination) |
| `AzureGateway` / `GCPGateway` | Unit-tested by injecting stand-in SDK clients and checking the calls they get (right scope, right principal, right duration bounds, right filters) - this proves Plumbline's own wiring, not that Azure's or GCP's real APIs behave as documented. Unlike `Boto3Gateway`, **neither has been exercised against a live account**; there is no moto-equivalent emulator for either readily available. Treat them as correct-against-the-docs, not field-tested. |
| LLM explainer | Against a **mock** HTTP transport only. Never called against the live API in this repo's tests |
| Key rules | Mutation-checked by hand: breaking the scope check, the contract-end cap, separation of duties, or the GCP IAM-binding removal in `revoke_sessions` all make tests fail. A latent argument-order bug in `classify_action`'s pattern matching (found while adding GCP's `*.setIamPolicy` wildcard, which never actually matched anything until fixed) is also now covered. |
| Detection quality | Simulated scenarios only (see below) |
| Real AWS | Scope enforcement, the orphan scan, and revocation were exercised on a personal AWS test account: a real credential issued by Plumbline stopped working immediately after revoke (AWS returned an explicit deny), and the orphan scan correctly flagged an untagged contractor role |

### Evaluation (simulated data)

`python -m eval.run_eval --seed 7 --per-scenario 12` runs 264 simulated scenarios and writes [eval/RESULTS.md](eval/RESULTS.md).

| Measure | Result |
|---|---|
| False alarms on benign scenarios | 0.0% |
| Designed-for scenarios handled as expected | 100.0% |
| Known-hard harmful scenarios that raised any alert | 0.0% |
| All harmful scenarios that raised any alert | 81.2% |

**How to read this honestly:** the scenarios were written by the people who wrote the rules, so the 100% shows the code does what it was designed to do and guards against regressions. It says nothing about how well Plumbline would do against real attackers. The first version of the anomaly detector raised false alarms on 11% of benign scenarios (a busy day and a contractor working from a new address); the Isolation Forest was too eager and the volume threshold too low, and both were corrected. The thresholds were therefore adjusted with these scenarios in view. Three harmful cases are caught by **none** of the current checks, and the results say so: exfiltration by a brand-new contractor with no history to compare against, an attacker who behaves exactly like the contractor's normal day, and allowed reads that do not match the stated purpose.

## Limitations to know about

- **Revocation ends every earlier session on the contract's role,** not one person's. That is how AWS allows it (a Deny keyed on `aws:TokenIssueTime`), and it is why each contract needs its own role.
- **Temporary credentials cannot be revoked individually and expire on their own.** Plumbline's expiry records follow the real credential expiry.
- **STS sessions last at least 15 minutes,** and an inline session policy is limited to 2,048 characters. Requests that don't fit are refused.
- **CloudTrail `LookupEvents`** covers management events from the last 90 days only, is rate limited, and events can arrive several minutes late. Run reviews some time after a session ends. Data events (for example S3 object reads) are only visible if you have enabled them in CloudTrail.
- **The audit log is tamper-evident, not tamper-proof.** Someone who can rewrite the whole database can rebuild a valid chain, and removing the newest entries is only caught if you saved an earlier head hash elsewhere.
- **Policies:** only `Allow` statements without `Condition`, `NotAction`, `NotResource` or `Principal` are accepted, because Plumbline does not evaluate those and will not pretend to. Scope checks use wildcard matching and fail closed.
- **Baselines are only as good as the history.** Earlier sessions are assumed to be legitimate. A new contractor has no baseline, so only the multiple-address check works for them. The Isolation Forest needs at least 20 earlier sessions and is skipped if scikit-learn is not installed (`pip install -r requirements-ml.txt`).
- **A finding, once open, is not updated with later evidence.** If a grant already has an open `OUT_OF_SCOPE_ATTEMPT` finding and a CloudTrail event for it arrives late (events can lag several minutes), that event is not added to the finding or reported separately, because dedup is keyed per grant, not per event. Confirmed in real-AWS testing.
- **The change-risk scorer only knows what it is told.** `review_count`, `has_rollback_plan` and the rest are supplied by whoever submits the change; nothing here verifies them against your source control or CI. It is a consistent, explainable scoring rule, not a fraud check.
- **The SLO burn-rate alert needs real traffic to mean anything.** The two-window thresholds are the published values for a 30-day window, scaled by window length; they have not been tuned against a real service's noise.
- **IAM-user contractors** are found by the orphan scan, but activity from long-lived keys is not matched to grants.
- **The stated purpose is free text.** The rules cannot judge it. The optional LLM explanation is asked to compare purpose and activity, and its answer is only trusted if its citations check out.
- **Azure and GCP narrowing is intent-only, not enforced.** Plumbline validates and audits a per-request scope on every provider, but only AWS can actually bound a single grant to less than its role's full permissions (an inline STS session policy). On Azure and GCP the credential (or, for Azure, the activated role) carries the contract's full role - see [Azure and GCP: what's the same, what's not](#azure-and-gcp-whats-the-same-whats-not).
- **GCP cannot revoke an already-issued token before it expires,** and Azure's and GCP's own documented propagation delays mean a revoked grant's access does not necessarily stop the instant `revoke()` returns on those two clouds, unlike AWS's Deny trick. Same table as above for the specifics.
- **Azure's orphan scan needs a Microsoft Graph client supplied by hand**, and reports a service principal's `created`/`last_used` as `None` rather than guessing, so the DORMANT check never fires for Azure principals yet (it has no sign-in-logs call wired up). GCP's and Azure's gateways report the same honest `None` for anything they're not actually told, rather than approximating it from AWS's shape.
- **Neither the Azure nor the GCP gateway has been run against a real account.** They are correct against the documented SDK call shapes and unit-tested with injected stand-in clients, the same way the rest of Plumbline's logic is tested - but AWS is the only cloud this project has actually pointed at a live environment.

## Not built yet

- Linking a change (module 2) to the access and contractor flow (module 1) — today they are two separate, independently useful features in one codebase, not yet one guardrail pipeline.
- Resource-level IAM Conditions (Azure ABAC, GCP conditional bindings) that would let a per-request scope actually be enforced on Azure and GCP, not just recorded and approved — see the narrowing limitation above.
- A live Azure and/or GCP account to validate the two new gateways against, the way AWS already has been.

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m eval.run_eval --seed 7 --per-scenario 12
```

## License

MIT. See `LICENSE`.
