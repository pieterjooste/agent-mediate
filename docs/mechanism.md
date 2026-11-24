# Agent-Mediate Mechanism Specification (`rulesVersion: "1.4.0"`)

- **Schema:** `agent-mediate/mechanism-spec/v1`
- **Rules Version (`RULES_VERSION`):** `1.4.0`
- **Canonical Rules Hash (`RULES_HASH`):** `10b48aa0d8a4a71808f5550f951ad128aa0af44b775b2c88c73ddb1dd1cee173`
- **Historical Rules Hash (`1.3.0`):** `8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4` (honored for transition pre-dispute clauses and historical outcome verification)
- **Machine-Readable Endpoint:** `GET /v1/rules` (`sha256Hex(canonicalJson(spec)) === rulesHash`)

Every platform-signed settlement instruction, `UNRESOLVED` certificate, transparency checkpoint, and co-signed `agent-mediate/clause/v1` embeds `rulesVersion` and `rulesHash` (RFC 8785 JCS + SHA-256 over `MECHANISM_SPEC`). Any change to the deterministic rules, domains, clamping, distance metric, or window limits changes `RULES_HASH` and requires a `RULES_VERSION` bump.

---

## 1. Issue Grid, Linear Utility, and No-Retraction Monotonicity

A confirmed dispute defines $1 \le m \le 5$ negotiable issues $I = \{i_1, \dots, i_m\}$. Each issue $i$ has:
- Inclusive domain $[i.\text{min},\, i.\text{max}]$ with granularity $i.\text{step} > 0$, where $(i.\text{max} - i.\text{min}) / i.\text{step}$ is an exact integer.
- Preference orientation $i.\text{claimantPrefers} \in \{\text{"higher"}, \text{"lower"}\}$ (the respondent strictly prefers the opposite direction).
- Designated performer $i.\text{obligor} \in \{\text{"claimant"}, \text{"respondent"}\}$.

### Grid Alignment & Even-Half Rounding (`H-10`)
Every package $x \in \mathbb{R}^m$ submitted or output by the mechanism lies on the exact step grid $x_i = i.\text{min} + k \cdot i.\text{step}$ ($k \in \mathbb{Z}$). Exact half-step midpoints snap to the **even** grid index $k$ so rounding has zero directional bias toward claimant or respondent. Under `v1.4.0` (`H-10`), `snap()` uses exact integer arithmetic on integer grids and ULP-scaled index tolerances (capped at `0.25`, matching `gridTolerance`) on fractional grids (e.g., USD cents and `1e-6` ratios), while `ShareBox` carries exact grid-snapped `[minVal, maxVal]` bounds without lossy share round-tripping.

### Normalised Share & Additive Utility
For value $x_i \in [i.\text{min}, i.\text{max}]$, the claimant's normalised share is:

$$s_C(i, x_i) = \begin{cases} \dfrac{x_i - i.\text{min}}{i.\text{max} - i.\text{min}} & \text{if } i.\text{claimantPrefers} = \text{"higher"} \\[8pt] \dfrac{i.\text{max} - x_i}{i.\text{max} - i.\text{min}} & \text{if } i.\text{claimantPrefers} = \text{"lower"} \end{cases}$$

and the respondent's share is $s_R(i, x_i) = 1 - s_C(i, x_i)$. Given a party $p$'s confidential Round-1 non-negative weights $w_p$ ($\sum_i w_{p,i} = 1$), party $p$'s normalised utility is $U_p(x) = \sum_{i \in I} w_{p,i}\, s_p(i, x_i) \in [0, 1]$.

### Per-Issue No-Retraction Rule
In every bargaining round $r > 1$ (and in final-offer determination), each party's new offer $x^{(r)}$ must concede or hold steady on **every** issue relative to its previous offer $x^{(r-1)}$:
- Claimant: $s_C(i, x^{(r)}_i) \le s_C(i, x^{(r-1)}_i)$ for all $i \in I$.
- Respondent: $s_C(i, x^{(r)}_i) \ge s_C(i, x^{(r-1)}_i)$ for all $i \in I$.

Violations are rejected immediately with `422 RETRACTION`.

---

## 2. Principal-Signed Mandates and Confidential Inputs

### Mandates (`agent-mediate/mandate/v1`)
Principals authorise agents via Ed25519-signed mandates specifying:
- `bounds`: inclusive per-issue authority intervals $[B_{p,i}^{\min}, B_{p,i}^{\max}]$ for voluntary bargaining (`OVERLAP_MIDPOINT`, `PROPOSAL_ACCEPTED`, `SETTLEMENT_IMPROVED`).
- Optional `determinationConsent: true` and optional `determinationBounds` (`MECH-1`, `D126`). `determinationBounds` may be **tighter or wider** than voluntary `bounds`, enabling two-tier mandates where principals pair cautious voluntary bargaining `bounds` with wider fallback `determinationBounds` so non-overlapping voluntary mandates can still resolve via `FINAL_OFFER_DETERMINATION`.
- `expiresAt` (must outlive `bargainingWallClockMs`, plus `determinationTimeoutMs` when `determinationConsent` is enabled; `MECH-5`), monotonic `issuedAt` on replacement (`CR2-11`), and optional `scope: { contractHash, counterpartyId }` (`H2`).
- When a co-signed pre-dispute `agent-mediate/clause/v1` specifies non-empty `terms.issueTemplates`, `proposedIssues` at filing must be a non-empty subset matching each template's `id`, `claimantPrefers`, `obligor`, `unit`, and `step` with on-grid `[min, max]` inside `[template.min, template.max]` (`422 CLAUSE_VIOLATION` on mismatch; `SEC-2`). Mutually confirmed AI trade-off suggestions during `ISSUE_CONFIRMATION` remain permitted when both parties confirm with valid mandates.

### Resolving Non-Overlapping Mandates (`D126`, `D127`)
When principals' initial single-issue or narrow mandates do not overlap ($B_C \cap B_R = \emptyset$), three mechanism paths enable settlement without compromising principal control or Round-1 confidentiality:
1. **Adopting AI-Suggested Trade-Off Issues (`REJECT_ISSUES.adoptSuggestedIds`):** During `ISSUE_CONFIRMATION` (when `proposalCount < maxIssueProposals`), either party may call `REJECT_ISSUES` bound to the current `issuesHash` (`409 HASH_MISMATCH` if stale, `BUG-3`) with optional `adoptSuggestedIds` (`1..2` issue IDs from `advisory.suggestedIssues`). Omitting `adoptSuggestedIds` resets the next `PROPOSE_ISSUES` to `filing.proposedIssues`; passing `adoptSuggestedIds` preserves `filing.proposedIssues`, consecutively adopted prior suggestions (`priorAdoptedSuggestedIds`), mutually mandated suggestions, and the newly adopted IDs (`total <= 5`, zero extra LLM calls), allowing both parties to call `CONFIRM_ISSUES` with multi-issue replacement mandates and logroll across issues.
2. **In-Place Monotonic Principal Escalation (`UPDATE_MANDATE`):** During `BARGAINING` or `DETERMINATION`, either party may submit up to `MAX_MANDATE_UPDATES = 3` replacement mandates (`POST /v1/disputes/{id}/mandate`), surfaced in `nextActions` whenever an `openProposal` exceeds the party's current mandate (`proposalWithinYourMandate === false`), in `DETERMINATION`, or in single-issue rounds where standing offers remain disjoint. The replacement must come from the **same** `principalId` with strictly newer `issuedAt`, `next.expiresAt >= previous.expiresAt`, **identical** `determinationConsent` (`determinationConsent` is frozen once `BARGAINING` opens so neither party can unilaterally flip determination opt-in after seeing bargaining dynamics, `SEC-1`), and raw + grid-clamped superset bounds ($B'_p \supseteq B_p$, plus $D'_p \supseteq D_p$ when `determinationConsent` is enabled; `BUG-1`) covering Round-1 `declared.limits` and any standing/in-round offer. When both mandates consent to determination, bargaining offers must also stay within `determinationBounds` on every issue (`BUG-7`) so no party can concede past its determination authority during bargaining. Round-1 `private` (`weights`, `walkaway`, `limits`) stays **strictly frozen** (`M13` / `MECH-8`); `UPDATE_MANDATE` appends an opaque `"internal"` `MANDATE_REGISTERED` link in `/audit` and redacts counterparty `/signatures` rows to `action: "confidential_action"` with `agentId: null` (`SEC-1`).
3. **Two-Tier `determinationBounds`:** Setting `determinationConsent: true` with `determinationBounds` wider than voluntary `bounds` resolves deadlocked bargaining via `FINAL_OFFER_DETERMINATION` without manual escalation.

### Round-1 Confidential Inputs (`private`)
With its first offer, each party submits `private: { weights, walkaway, limits? }`, frozen for the remainder of the dispute:
- `walkaway` ($W_p$) must lie on the grid and inside `mandate.bounds` (`MECH-5`).
- Optional `limits` ($L_{p,i} = [L_{p,i}^{\min}, L_{p,i}^{\max}]$) restrict platform proposals and post-settlement Pareto improvements to a feasible sub-box containing $W_p$ inside `mandate.bounds` (`MECH-7`).
- Confidential inputs never enter any LLM prompt and never leave the submitting party's own `PartyView`.

---

## 3. Crossing-Offer Settlement (`OVERLAP_MIDPOINT`, `MECH-6`)

When Round $r$ closes with standing offers $(O_C, O_R)$, offers **cross** if and only if each party's utility from the counterparty's offer meets or exceeds its utility from its own offer under its declared weights (for single-issue disputes, $s_C(O_R) \ge s_C(O_C)$).

1. Compute the per-issue grid-snapped midpoint $M_i = \text{snap}_{\text{even}}\!\left(\tfrac{1}{2}(O_{C,i} + O_{R,i})\right)$.
2. If $M$ lies inside both parties' `mandate.bounds`, settle at $M$.
3. Otherwise (`MECH-6`), clamp overflowing issues to the intersection box $B_C \cap B_R$ and greedily step compensating issues within $B_C \cap B_R$ on the step grid to minimise $\max_p \max(0,\, U_p(O_p) - U_p(x))$ subject to $U_C(x) \ge U_C(O_C)$ and $U_R(x) \ge U_R(O_R)$ whenever feasible inside $B_C \cap B_R$.

---

## 4. Single-Negotiating-Text Platform Proposals (`PROPOSAL_ACCEPTED`, `MECH-7`, `D75`, `SEC3-5`)

From `proposalFromRound` (default Round 2), the platform presents an `openProposal` every round:

### Secret Pair-Keyed Split $\alpha \in [0.3, 0.7]$ & Creation-Time Commitments
- At filing, the platform derives `proposalKey = HMAC-SHA256(PROPOSAL_SECRET, "agent-mediate/proposal-key/v1\n" + sortedPair + "\n" + contractHash)` (or, in unkeyed `"salted"` mode, the one-way per-dispute `proposalSalt = SHA256(auditSalt + ":" + disputeId + ":proposal-split")`, never raw `audit.salt`, `M8`) and publishes `proposalKeyCommitment = SHA256("agent-mediate/proposal-key-commit/v1\n" + disputeId + "\n" + mode + "\n" + keyOrSalt)` in `DISPUTE_FILED` **before** either party submits Round-1 confidential inputs (`SEC3-5`).
- On Round-1 submission, each party $p$ receives a personal 256-bit blinding salt `partySalt` and `declaredCommitment = SHA256("agent-mediate/declared-input-commit/v1\ncommit\n" + disputeId + "\n" + p + "\n" + partySalt + "\n" + canonicalJson(private_p))`, anchored into the `/audit` hash chain and recorded on the signed outcome document.
- $\alpha \in [0.3, 0.7]$ (`E[\alpha] = 0.5`) is derived deterministically via `HMAC-SHA256(proposalKey, "agent-mediate/proposal-split/v1\n" + canonicalJson(privates))` in `"keyed"` mode (or from `proposalSalt` in `"salted"` mode). Keeping $\alpha$ secret prevents a single party from inverting $P = W_C + \alpha(W_R - W_C)$ to recover the counterparty's low-entropy walkaway (`H1`). Because `"keyed"` `proposalKey` is shared across disputes for `(pair, contractHash)`, a live `"keyed"` `proposalKey` is **never** disclosed to a disputing party (`H5`: doing so would break walkaway hiding in subsequent disputes between that pair); `"keyed"` `verifyProposalOpening` (binding `expectedIssuesHash`) is intended strictly for a confidentiality-bound independent auditor (or after rotating `PROPOSAL_SECRET`), whereas `"salted"` mode opens only the per-dispute `proposalSalt`.

### Constrained Asymmetric Nash Optimisation & Non-Interference Stand-Ins
- Let feasible box $\mathcal{F} = L_C \cap L_R$ (defaulting omitted `limits` to $[i.\text{min}, i.\text{max}]$).
- The platform runs a deterministic **discrete search** over the grid points of $\mathcal{F}$ for a package $x$ with $U_C(x) \ge U_C(W_C)$ and $U_R(x) \ge U_R(W_R)$ (to within $10^{-9}$). It solves the continuous linear frontier of $\mathcal{F}$, then snaps the single fractional pivot issue to its floor and ceiling grid values and recursively re-optimises the remaining issues on each sub-box (`FS-H1`). If the search finds such a package (`settles = true`), both parties see the visited package maximising:

  $$(U_C(x) - U_C(W_C))^{\alpha}\,(U_R(x) - U_R(W_R))^{1-\alpha}$$

  (ties within $10^{-9}$ break by smaller distance from the continuous pivot value, then by the even grid index of the pivot, `FS-M4b`). If both parties respond `"accept"` and $x \in B_C \cap B_R$, the dispute settles with `method: "PROPOSAL_ACCEPTED"`.
- **The search is best-effort, not exhaustive (D125, `CR-CORE-M1`, `CR-CORE-L5`).** On coarse multi-issue grids with a very narrow zone of agreement it can miss an on-grid package both parties would accept: about 0.1% of random 3-issue disputes that have such a package, and none of 20,000 random 2-issue disputes with strictly positive surplus. A miss is never a wrong settlement; it only means no settling proposal is shown that round (the parties see stand-ins, below), and bargaining, final-offer determination and every other guarantee continue unchanged. Note on historical verifiability (`CR-CORE-L5`): recursive multi-issue pivot snapping (`FS-H1`) and even-grid-index midpoint tie-breaking (`FS-M4b`) took effect on **2026-11-05** under `RULES_VERSION = "1.1.0"`; proposal openings (`verifyProposalOpening`) from pre-2026-11-05 multi-issue or odd-step disputes may differ on round proposals while their signed outcomes and audit chains remain valid. An exact, bounded branch-and-bound search is deferred to a future rules version, together with dual-version proposal verification.
- If no mutually acceptable zone exists in $\mathcal{F}$ (`settles = false`, never disclosed), each party $p$ sees a deterministic reflected stand-in optimized strictly over its **own** box $L_p$ (never $L_C \cap L_R$, preventing counterparty `private.limits` boundary clamping, `H-09`) at or above $U_p(W_p)$, folding any joint or disjoint limit deficit into the scalar reflected disagreement utility blinded by secret $\alpha$ (`CR2-2`, `D75`, `H-09`). Accepting a stand-in behaves identically to a counterparty rejection, preserving strict non-interference across arbitrary counterparty walkaways and limits.

---

## 5. Post-Settlement Pareto Frontier Improvement (`MECH-10`, `H-09`)

When a multi-issue dispute settles with `EXECUTION_PENDING`, the platform searches the **full issue grid** (never optimizing against secret `mandate.bounds` or `private.limits` — `SA-CORE-M2`, `H-09`) for the grid package maximising the Nash product above the settled baseline $T$ (**never** over secret walkaways $W_p$) using the dispute's secret per-dispute split $\alpha \in [0.3, 0.7]$ (`H-09`, preventing algebraic weight inversion from a fixed public `0.5` split). The improvement opens in `execution.improvement` if and only if the candidate weakly improves both parties ($U_C(x) \ge U_C(T)$, $U_R(x) \ge U_R(T)$), raises combined utility by more than $10^{-6}$, and passes post-hoc membership checks inside both parties' `mandate.bounds` and declared `private.limits`.
- Individual responses remain masked until resolved.
- If both parties submit `accept` before any execution proof is filed, `SETTLEMENT_IMPROVED` upgrades the settled terms and records a new signed snapshot in `dispute_outcomes`.

---

## 6. Stall Detection (`MECH-3`), Wall-Clock Guard (`MECH-4`), and Outage Mandate Guard (`M-10`)

- **Gap:** $\text{gap}_r = \frac{1}{m}\sum_{i \in I} \max(0,\, s_C(i, O_{C,i}) - s_C(i, O_{R,i})) \in [0, 1]$.
- **Relative Progress (`MECH-3`):** Round $r \ge 2$ makes progress when $\text{gap}_{r-1} - \text{gap}_r \ge \text{stallThreshold} \cdot \text{gap}_{r-1}$ (default `stallThreshold = 0.05` over `stallWindow = 2` consecutive transitions). Using relative reduction avoids false `STALLED` terminations when parties actively concede inside a narrow $< 5\%$ gap.
- **Full-Window Guard (`MECH-4`):** Round $r + 1$ opens only if $r < \text{maxRounds}$ and $\text{wallClockDeadline} - \text{now} \ge \text{roundTimeoutMs}$.
- **Outage Mandate Expiry Guard (`M-10`):** When a recorded platform outage extends stage deadlines (`extendDeadlines`), principal-signed `mandate.expiresAt` is never mutated by the platform. At `CONFIRM_ISSUES`, before entering `BARGAINING`, both parties' mandates are re-verified against `now + requiredHorizon`; if the first confirmer's mandate became stale during the outage, their confirmation resets so they can re-confirm with a renewed mandate (or let `ISSUE_CONFIRMATION` close cleanly). Inside `resolveRound`, expired mandates neither increment `misses` nor trigger adverse `TIMEOUT` / `MISSED_ROUNDS`; instead bargaining closes cleanly via `NO_OVERLAP_AT_CAP`.

---

## 7. Contractual Binding Final-Offer Determination (`MECH-1`, `MECH-8`)

> **Legal Character (`D52`):** Contractual final-offer determination is an automated mathematical formula pre-agreed by both principals in signed mandates (`determinationConsent: true`), **not** statutory arbitration, adjudication, or an arbitral award.

When bargaining ends `STALLED` or `NO_OVERLAP_AT_CAP` and **both** active principal-signed mandates carry `determinationConsent: true`:
1. **Offer-Independent Reference (`MECH-8`):** The reference package $R^*$ is computed solely from the frozen Round-1 declared inputs (`declaredReferenceTerms`: symmetric $\alpha = 0.5$ Nash solution over $L_C \cap L_R$ when a zone exists, else per-issue grid midpoint of $(W_C, W_R)$). Conceding generously during bargaining never shifts $R^*$ against the conceding party.
2. **Final Offers & Mean-Weight Distance (`MECH-8`):** Each party may submit one final offer within `determinationBounds` (defaulting to its last bargaining offer if omitted). Offers are scored by mean-declared-weight normalised $L_1$ distance:

   $$d(O_p, R^*) = \sum_{i \in I} \frac{w_{C,i} + w_{R,i}}{2} \cdot \frac{|O_{p,i} - R^*_i|}{i.\text{max} - i.\text{min}}$$

   preventing low-weight-issue sacrifice gaming. Exact ties break deterministically via `SHA256(auditSalt + ":" + disputeId + ":arbitration-tiebreak")`.
3. **Bilateral Mandate Gate (`MECH-1`):** The closer final offer settles as `FINAL_OFFER_DETERMINATION` if and only if it lies within **both** parties' signed `determinationBounds`; otherwise the dispute ends `UNRESOLVED` with `DETERMINATION_FAILED`.

---

## 8. Execution Verification (`MECH-2`)

- **Zero-Obligation Immediate `HONORED` (`MECH-2`):** An issue settled at the obligee's worst extreme (e.g. `refundUsd = 0`) creates no obligation. If `obligors` is empty, the dispute settles immediately as `HONORED`.
- **Proof, Confirmation & Contest (`MECH-2`):** Obligors submit `SUBMIT_EXECUTION_PROOF`; obligees call `CONFIRM_EXECUTION` or `CONTEST_EXECUTION`. At `executionDeadline`, an obligor with uncontested proof is recorded as `HONORED` (preventing a silent obligee from manufacturing a breach), whereas missing or contested proof transitions to `BREACH_REPORTED`.

---

## 9. Cryptographic Verifiability (`SEC3-4`, `SEC3-5`, `KEY-1`, `DISC-12`)

1. **Transition-Signed Immutable Outcomes (`SEC3-4`):** Outcomes (`SETTLED`, `SETTLEMENT_IMPROVED`, `HONORED`, `BREACH_REPORTED`, `UNRESOLVED`, each carrying `outcomeHash` in the audit chain, `M7`) are signed with `Ed25519Signature2026` (`agent-mediate/document/v2`, binding `keyId` and `created`; no `expiresAt`, because outcomes are permanent records, `D119`) inside the state-transition database transaction and stored in the append-only `dispute_outcomes` table. `GET /v1/disputes/{id}/outcome` verifies the stored signature, `auditRoot`, `termsHash`, and `outcomeHash` inside a snapshot-consistent `REPEATABLE READ` transaction and never signs on read. A snapshot whose signing key is later revoked is superseded by a re-signed snapshot at the same audit position (`revision`), never by editing the original.
2. **Party Request Signature Proofs (`SEC3-5`, `SEC-1`):** Every party mutation's verified RFC 9421 Ed25519 proof (covering only the allowlisted components `@method`, `@target-uri`, `content-digest`, and `idempotency-key`, and bound to `(disputeId, action, agentId)`, `M1`/`M6`) is stored in the append-only `dispute_signatures` table and served at `GET /v1/disputes/{id}/signatures` (full proofs for the caller's own actions and public-body counterparty actions; `{ redacted: true, action: "confidential_action", agentId: null, proofHash }` commitments for confidential-body counterparty actions).
3. **Key History & Compromise Handling (`KEY-1`):** `GET /.well-known/key-history.json` publishes the signed `agent-mediate/key-history/v1` chain (`active`, `retired`, `revoked`). Retired keys remain verifiable within `[validFrom, validUntil]`; revoked keys are rejected by `verifyDocumentWithKeyHistory` (clients pinned out of band to a compromised `platformDid` check that pin first and must re-pin to the rotated active key, `M11`).
4. **Merkle Checkpoints & Base L2 Anchoring (`SEC3-5`, `DISC-12`):** Scheduled daily checkpoints (`GET /v1/transparency/checkpoint`, `GET /v1/transparency/checkpoints/{seq}`) publish signed binary SHA-256 Merkle roots using the RFC 6962 §2.1 largest-power-of-two split topology with string domain prefixes (`agent-mediate/checkpoint-leaf/v1\n`, `agent-mediate/checkpoint-node/v1\n`) over unique-`disputeId` snapshot tuples `(disputeId, status, auditSeq, auditHead, outcomeHash)` and deterministic 44-byte Base calldata (`0x414d4350` + 8-byte `checkpointSeq` + 32-byte `merkleRoot`). `GET /v1/disputes/{id}/audit` proves $O(\log N)$ inclusion (`expectedTotalLeaves === disputeCount`) against the latest **anchored** checkpoint containing the dispute (falling back to the latest unanchored one); because leaves are per-checkpoint dispute snapshots rather than an append-only event log, cross-party split views are ruled out by comparing `(checkpointSeq, merkleRoot, leafIndex)` against Base L2 calldata (`M3`).
