/**
 * Local Practice Counterparty Bot CLI (`examples/practice-respondent.ts`).
 *
 * Spins up an automated respondent agent that polls for incoming disputes (against
 * https://api.ai-agents-mediation.com by default, or any AGENT_MEDIATE_URL) and plays
 * through any single- or multi-issue commercial mediation automatically — joining,
 * submitting evidence, confirming issues, exchanging sealed offers with a hidden
 * walkaway, accepting improvements, and posting simulated execution proof.
 *
 * Usage:
 *   node examples/practice-respondent.ts
 *   AGENT_MEDIATE_URL=http://localhost:8080 node examples/practice-respondent.ts
 *   node examples/practice-respondent.ts --invite <inviteToken>
 */
import type { Issue, Package } from "@agent-mediate/core";
import {
  AgentMediateClient,
  agentKeyFromPem,
  generateAgentKey,
  sha256Hex,
  signMandate,
} from "@agent-mediate/sdk";

const baseUrl = (process.env.AGENT_MEDIATE_URL ?? "https://api.ai-agents-mediation.com").replace(/\/+$/, "");
const key = process.env.RESPONDENT_PRIVATE_KEY
  ? agentKeyFromPem(process.env.RESPONDENT_PRIVATE_KEY.replace(/\\n/g, "\n"))
  : generateAgentKey();

const args = process.argv.slice(2);
const once = args.includes("--once") || process.env.ONCE === "1";
const inviteIdx = args.indexOf("--invite");
const inviteToken = inviteIdx >= 0 ? args[inviteIdx + 1] : undefined;
const pollMs = Math.max(500, Number(process.env.POLL_MS ?? 1_500) || 1_500);
const round1Concession = Number(process.env.PRACTICE_ROUND1_CONCESSION ?? 0.25);
const walkawayConcession = Number(process.env.PRACTICE_WALKAWAY_CONCESSION ?? 0.65);

const client = new AgentMediateClient({
  baseUrl,
  agentKey: key,
  ...(process.env.AGENT_MEDIATE_PLATFORM_DID ? { platformDid: process.env.AGENT_MEDIATE_PLATFORM_DID } : {}),
});

function decimalsOf(n: number): number {
  const s = String(n);
  if (s.includes("e-")) {
    const exp = Number.parseInt(s.split("e-")[1] ?? "0", 10);
    return Number.isFinite(exp) ? Math.min(10, Math.max(0, exp)) : 6;
  }
  const dot = s.indexOf(".");
  return dot < 0 ? 0 : Math.min(10, s.length - dot - 1);
}

function snapConcession(issue: Issue, concessionTowardClaimant: number): number {
  const frac = Math.max(0, Math.min(1, concessionTowardClaimant));
  const span = issue.max - issue.min;
  if (span <= 0 || issue.step <= 0) return issue.min;
  const maxSteps = Math.max(0, Math.floor((span + issue.step * 1e-9) / issue.step));
  const posFromMin = issue.claimantPrefers === "higher" ? frac : 1 - frac;
  const k = Math.max(0, Math.min(maxSteps, Math.round(maxSteps * posFromMin)));
  const precision = Math.max(decimalsOf(issue.min), decimalsOf(issue.step));
  return Math.max(issue.min, Math.min(issue.max, Number((issue.min + k * issue.step).toFixed(precision))));
}

function buildUniformWeights(issues: readonly Issue[]): Record<string, number> {
  const out: Record<string, number> = {};
  const base = Math.floor(1_000_000 / issues.length) / 1_000_000;
  let sum = 0;
  for (let i = 0; i < issues.length; i++) {
    const id = issues[i]!.id;
    if (i === issues.length - 1) out[id] = Number((1 - sum).toFixed(6));
    else {
      out[id] = base;
      sum = Number((sum + base).toFixed(6));
    }
  }
  return out;
}

function buildPackage(issues: readonly Issue[], concession: number, prevOffer?: Package | null): Package {
  const pkg: Package = {};
  for (const iss of issues) {
    let v = snapConcession(iss, concession);
    if (prevOffer && typeof prevOffer[iss.id] === "number") {
      v = iss.claimantPrefers === "higher" ? Math.max(prevOffer[iss.id]!, v) : Math.min(prevOffer[iss.id]!, v);
    }
    pkg[iss.id] = v;
  }
  return pkg;
}

function fullBounds(issues: readonly Issue[]): Record<string, { min: number; max: number }> {
  return Object.fromEntries(issues.map((iss) => [iss.id, { min: iss.min, max: iss.max }]));
}

async function advanceDispute(disputeId: string): Promise<boolean> {
  let acted = false;
  for (let step = 0; step < 6; step++) {
    const { view } = await client.getDispute(disputeId, { view: "full" });
    if (view.you !== "respondent") return acted;
    const next = new Set(view.nextActions ?? []);

    if (view.status === "AWAITING_RESPONDENT" && next.has("join_dispute")) {
      const proposed = view.issueNegotiation.proposed ?? [];
      const bounds = proposed.length > 0 ? fullBounds(proposed) : { practicePlaceholder: { min: 0, max: 1 } };
      await client.join(disputeId, {
        mandate: signMandate(
          {
            id: `mnd_local_${disputeId.slice(0, 20)}_join`,
            principalId: key.did,
            agentId: key.did,
            scope: { contractHash: view.contractHash, counterpartyId: view.counterpartId },
            bounds,
            determinationConsent: true,
            determinationBounds: bounds,
            issuedAt: Date.now() - 60_000,
            expiresAt: Date.now() + 30 * 86_400_000,
          },
          key,
        ),
      });
      console.log(`[${disputeId}] joined ($0.00)`);
      acted = true;
      continue;
    }

    if (view.status === "EVIDENCE") {
      if (!view.evidence.some((e) => e.submittedBy === "respondent") && next.has("submit_evidence")) {
        await client.submitEvidence(disputeId, [
          {
            id: "practice_vendor_log_1",
            kind: "service_telemetry",
            sha256: sha256Hex(`practice-local-evidence:${disputeId}`),
            description: "Local practice respondent telemetry log commitment.",
          },
        ]);
        console.log(`[${disputeId}] submitted evidence commitment`);
        acted = true;
        continue;
      }
      if (next.has("close_evidence")) {
        await client.closeEvidence(disputeId);
        console.log(`[${disputeId}] closed evidence`);
        acted = true;
        continue;
      }
      break;
    }

    if (
      view.status === "ISSUE_CONFIRMATION" &&
      !view.issueNegotiation.youConfirmed &&
      view.issueNegotiation.proposedHash &&
      view.issueNegotiation.proposed &&
      next.has("confirm_issues")
    ) {
      const proposed = view.issueNegotiation.proposed;
      const currentBounds = view.yourMandate?.bounds ?? {};
      const missingCoverage = proposed.some(
        (iss) => !currentBounds[iss.id] || currentBounds[iss.id]!.min > iss.min || currentBounds[iss.id]!.max < iss.max,
      );
      const replacementMandate = missingCoverage
        ? signMandate(
            {
              id: `mnd_local_${disputeId.slice(0, 20)}_iss${view.issueNegotiation.proposalCount}`,
              principalId: key.did,
              agentId: key.did,
              scope: { contractHash: view.contractHash, counterpartyId: view.counterpartId },
              bounds: fullBounds(proposed),
              determinationConsent: true,
              determinationBounds: fullBounds(proposed),
              issuedAt: Math.min(Date.now(), Math.max(Date.now() - 10_000, (view.yourMandate?.issuedAt ?? 0) + 1)),
              expiresAt: Date.now() + 30 * 86_400_000,
            },
            key,
          )
        : undefined;
      await client.confirmIssues(disputeId, view.issueNegotiation.proposedHash, replacementMandate);
      console.log(`[${disputeId}] confirmed issues (${proposed.map((i) => i.id).join(", ")})`);
      acted = true;
      continue;
    }

    if (view.status === "BARGAINING" && view.bargaining && !view.bargaining.yourCurrentSubmission && view.issues) {
      const round = view.bargaining.round;
      const maxRounds = Math.max(2, view.rules.maxRounds);
      const prev = [...view.bargaining.yourHistory].reverse().find((h) => h.offer !== null)?.offer ?? null;
      const progress = Math.min(1, (round - 1) / (maxRounds - 1));
      const offer = buildPackage(view.issues, round1Concession + (walkawayConcession - round1Concession) * progress, prev);
      const proposalResponse = view.bargaining.openProposal
        ? view.proposalMeetsYourWalkaway === true ||
          (view.proposalMeetsYourWalkaway === null && view.proposalWithinYourMandate === true)
          ? "accept"
          : "reject"
        : undefined;
      await client.submitOffer(disputeId, round, {
        offer,
        ...(!view.bargaining.yourPrivate
          ? {
              private: {
                weights: buildUniformWeights(view.issues),
                walkaway: buildPackage(view.issues, walkawayConcession),
              },
            }
          : {}),
        ...(proposalResponse ? { proposalResponse } : {}),
      });
      console.log(
        `[${disputeId}] submitted round ${round} offer ${JSON.stringify(offer)}${proposalResponse ? ` (proposal: ${proposalResponse})` : ""}`,
      );
      acted = true;
      continue;
    }

    if (
      view.status === "DETERMINATION" &&
      view.determination &&
      !view.determination.yourFinalOffer &&
      view.issues &&
      next.has("submit_final_offer")
    ) {
      const offer = buildPackage(view.issues, 0.5);
      await client.submitFinalOffer(disputeId, offer);
      console.log(`[${disputeId}] submitted final offer ${JSON.stringify(offer)}`);
      acted = true;
      continue;
    }

    if (view.status === "EXECUTION_PENDING" && view.execution) {
      if (
        view.execution.improvement?.status === "OPEN" &&
        view.execution.improvement.responses.respondent === null &&
        next.has("respond_improvement")
      ) {
        await client.respondImprovement(disputeId, "accept");
        console.log(`[${disputeId}] accepted post-settlement Pareto improvement`);
        acted = true;
        continue;
      }
      if (
        view.execution.obligors.includes("respondent") &&
        !view.execution.proofs.respondent &&
        next.has("submit_execution_proof")
      ) {
        await client.submitExecutionProof(disputeId, `practice-local-fulfillment:${disputeId}`);
        console.log(`[${disputeId}] submitted simulated execution proof`);
        acted = true;
        continue;
      }
      if (
        view.execution.obligors.includes("claimant") &&
        view.execution.proofs.claimant &&
        !view.execution.confirmed.claimant &&
        next.has("confirm_execution")
      ) {
        await client.confirmExecution(disputeId);
        console.log(`[${disputeId}] confirmed claimant execution`);
        acted = true;
        continue;
      }
    }

    break;
  }
  return acted;
}

console.log(`==> Agent-Mediate Local Practice Respondent`);
console.log(`    API:            ${baseUrl}`);
console.log(`    Respondent DID: ${client.did}`);
console.log(`    Strategy:       round-1 concession ${Math.round(round1Concession * 100)}%, hidden walkaway ${Math.round(walkawayConcession * 100)}%`);
console.log(`    File any $0.00 dispute naming respondentId="${client.did}" to watch it settle live.\n`);

if (inviteToken) {
  const accepted = await client.acceptInvite(inviteToken);
  console.log(`Accepted invite ${accepted.inviteId} (status=${accepted.status})`);
}

let running = true;
process.on("SIGINT", () => {
  running = false;
});
process.on("SIGTERM", () => {
  running = false;
});

while (running) {
  try {
    const { disputes } = await client.listDisputes({ role: "respondent", limit: 20 });
    for (const d of disputes) {
      if (d.status === "HONORED" || d.status === "BREACH_REPORTED" || d.status === "UNRESOLVED") continue;
      await advanceDispute(d.disputeId);
    }
  } catch (err) {
    console.error("Poll error:", err instanceof Error ? err.message : String(err));
  }
  if (once) break;
  await new Promise((r) => setTimeout(r, pollMs));
}
