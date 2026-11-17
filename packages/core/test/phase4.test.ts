import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildCheckpointMerkleTree,
  buildSettlementInstruction,
  buildUnresolvedCertificate,
  canonicalJson,
  CHECKPOINT_LEAF_DOMAIN,
  CHECKPOINT_NODE_DOMAIN,
  checkpointLeafHash,
  checkpointNodeHash,
  computeDeclaredInputCommitment,
  computeOutcomeHash,
  computeProposalKeyCommitment,
  computeTermsHash,
  decodeBaseAnchorCalldata,
  declaredReferenceTerms,
  derivePartyInputSalt,
  deriveProposalKey,
  deriveProposalSalt,
  EMPTY_MERKLE_ROOT,
  encodeBaseAnchorCalldata,
  issuesHash,
  MECHANISM_SPEC,
  RULES_HASH,
  RULES_VERSION,
  sha256Hex,
  verifyCheckpointInclusion,
  verifyProposalOpening,
  viewFor,
  type CheckpointLeafInput,
  type Issue,
  type PrivateInputs,
} from "../src/index.ts";
import { CLAIMANT, CONTRACT, CREDIT, Harness, REFUND, RESPONDENT, SALT, single } from "./helpers.ts";

const GOLDEN_RULES_HASH = "8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4";

describe("Phase 4 core verifiability primitives", () => {
  it("pins golden RULES_HASH and deep-freezes MECHANISM_SPEC against accidental mutation (DISC-11, M9)", () => {
    assert.equal(RULES_VERSION, "1.3.0");
    assert.equal(MECHANISM_SPEC.rulesVersion, RULES_VERSION);
    assert.equal(RULES_HASH, GOLDEN_RULES_HASH);
    assert.equal(RULES_HASH, sha256Hex(canonicalJson(MECHANISM_SPEC)));
    assert.equal(Object.isFrozen(MECHANISM_SPEC), true);
    assert.equal(Object.isFrozen(MECHANISM_SPEC.platformProposal), true);
    assert.equal(Object.isFrozen(MECHANISM_SPEC.platformProposal.splitRange), true);
    assert.equal(Object.isFrozen(MECHANISM_SPEC.issueNegotiation), true);
    assert.equal(Object.isFrozen(MECHANISM_SPEC.mandateEscalation), true);
    assert.equal(Object.isFrozen(MECHANISM_SPEC.defaults.windowsMs), true);
    assert.throws(() => {
      (MECHANISM_SPEC.grid as { maxIssues: number }).maxIssues = 99;
    }, TypeError);
  });

  it("canonicalizes integer-like keys in RFC 8785 UTF-16 code-unit order rather than V8 array-index order (H7)", () => {
    const obj: Record<string, unknown> = JSON.parse(
      '{"10":1,"9":2,"01":3,"a":4,"0":0,"4294967294":7,"4294967295":8,"__proto__":9,"nested":{"2":"b","10":"a"}}',
    );
    obj.omitted = undefined;
    assert.equal(
      canonicalJson(obj),
      '{"0":0,"01":3,"10":1,"4294967294":7,"4294967295":8,"9":2,"__proto__":9,"a":4,"nested":{"10":"a","2":"b"}}',
    );
    assert.equal(canonicalJson([-0, undefined, "x"]), '[0,null,"x"]');
  });

  it("commits termsHash and outcomeHash in SETTLED, SETTLEMENT_IMPROVED, and UNRESOLVED events (SEC3-4)", () => {
    // 1. Multi-issue crossing settlement followed by post-settlement Pareto improvement (MECH-10)
    const h = new Harness({ issues: [REFUND, CREDIT] }).toBargaining();
    const cPriv: PrivateInputs = {
      weights: { refundUsd: 0.2, serviceCreditUsd: 0.8 },
      walkaway: { refundUsd: 200, serviceCreditUsd: 100 },
    };
    const rPriv: PrivateInputs = {
      weights: { refundUsd: 0.8, serviceCreditUsd: 0.2 },
      walkaway: { refundUsd: 600, serviceCreditUsd: 300 },
    };
    // Offers cross cleanly on inefficient diagonal (500, 200) leaving Pareto headroom toward (200..400, 350..500)
    h.round(
      { offer: { refundUsd: 500, serviceCreditUsd: 200 }, private: cPriv },
      { offer: { refundUsd: 500, serviceCreditUsd: 200 }, private: rPriv },
    );
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind, "SETTLED");
    const settledEv = h.events.find((e) => e.type === "SETTLED");
    assert.ok(settledEv, "SETTLED event emitted");
    assert.equal(settledEv.data.termsHash, computeTermsHash(h.state.outcome.terms));
    assert.equal(settledEv.data.outcomeHash, computeOutcomeHash(h.state.outcome, h.state.status));

    assert.ok(h.state.execution?.improvement, "Pareto improvement proposal opened");
    h.send({ type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" });
    h.send({ type: "RESPOND_IMPROVEMENT", actor: "respondent", response: "accept" });
    assert.equal(h.state.outcome?.kind, "SETTLED");
    const improvedEv = h.events.find((e) => e.type === "SETTLEMENT_IMPROVED");
    assert.ok(improvedEv, "SETTLEMENT_IMPROVED event emitted");
    assert.equal(improvedEv.data.termsHash, computeTermsHash(h.state.outcome.terms));
    assert.equal(improvedEv.data.outcomeHash, computeOutcomeHash(h.state.outcome, h.state.status));
    assert.notEqual(improvedEv.data.termsHash, settledEv.data.termsHash);

    const doc = buildSettlementInstruction(h.state);
    assert.equal(doc.rulesHash, RULES_HASH);
    assert.equal(doc.termsHash, improvedEv.data.termsHash);
    assert.equal(doc.outcomeHash, improvedEv.data.outcomeHash);

    // 2. UNRESOLVED outcome event carries outcomeHash
    const u = new Harness().expire();
    assert.equal(u.state.status, "UNRESOLVED");
    const unresolvedEv = u.events.find((e) => e.type === "UNRESOLVED");
    assert.ok(unresolvedEv, "UNRESOLVED event emitted");
    assert.equal(unresolvedEv.data.outcomeHash, computeOutcomeHash(u.state.outcome!, u.state.status));
    const cert = buildUnresolvedCertificate(u.state);
    assert.equal(cert.rulesHash, RULES_HASH);
    assert.equal(cert.outcomeHash, unresolvedEv.data.outcomeHash);
  });

  it("commits proposalKeyCommitment at filing, blinds Round-1 declaredCommitments per party, and verifies opening (SEC3-5)", () => {
    const proposalKey = deriveProposalKey("platform-secret-32b-for-unit-test", CLAIMANT, RESPONDENT, CONTRACT);
    const h = new Harness({
      issues: [REFUND, CREDIT],
      proposalKey,
      determination: { claimant: true, respondent: true },
    }).toBargaining();

    const filedEv = h.events.find((e) => e.type === "DISPUTE_FILED")!;
    const expectedKeyCommit = computeProposalKeyCommitment("dsp_test", proposalKey, "keyed");
    assert.equal(filedEv.data.proposalKeyCommitment, expectedKeyCommit);
    assert.notEqual(expectedKeyCommit, computeProposalKeyCommitment("dsp_test", proposalKey, "salted"));

    const cPriv: PrivateInputs = {
      weights: { refundUsd: 0.6, serviceCreditUsd: 0.4 },
      walkaway: { refundUsd: 400, serviceCreditUsd: 150 },
    };
    const rPriv: PrivateInputs = {
      weights: { refundUsd: 0.5, serviceCreditUsd: 0.5 },
      walkaway: { refundUsd: 650, serviceCreditUsd: 350 },
    };

    // Round 1: non-crossing offers so Round 2 opens with a platform proposal
    h.round(
      { offer: { refundUsd: 900, serviceCreditUsd: 450 }, private: cPriv },
      { offer: { refundUsd: 100, serviceCreditUsd: 50 }, private: rPriv },
    );
    assert.equal(h.state.status, "BARGAINING");
    assert.equal(h.state.bargaining?.round, 2);

    const cView = viewFor(h.state, "claimant");
    const rView = viewFor(h.state, "respondent");
    assert.equal(cView.proposalKeyCommitment, expectedKeyCommit);
    assert.ok(cView.bargaining?.yourDeclaredVerification);
    assert.ok(rView.bargaining?.yourDeclaredVerification);

    // Counterparty blinding: claimant never sees respondent's salt, and different auditSalts yield distinct 256-bit salts
    assert.notEqual(cView.bargaining.yourDeclaredVerification.partySalt, rView.bargaining.yourDeclaredVerification.partySalt);
    assert.equal(JSON.stringify(cView).includes(rView.bargaining.yourDeclaredVerification.partySalt), false);
    const altSalt = derivePartyInputSalt("different-audit-salt".padEnd(48, "z"), "dsp_test", "respondent");
    assert.notEqual(altSalt, rView.bargaining.yourDeclaredVerification.partySalt);
    assert.notEqual(
      computeDeclaredInputCommitment("dsp_test", "respondent", altSalt, rPriv),
      rView.bargaining.yourDeclaredVerification.commitment,
    );

    const cProposal = cView.bargaining.openProposal!.terms;
    const rProposal = rView.bargaining.openProposal!.terms;
    assert.deepEqual(cProposal, rProposal, "overlapping walkaway zone presents identical Nash proposal to both parties");

    // Stall into DETERMINATION so we also verify declaredReferenceTerms (MECH-8)
    h.round(
      { offer: { refundUsd: 900, serviceCreditUsd: 450 }, response: "reject" },
      { offer: { refundUsd: 100, serviceCreditUsd: 50 }, response: "reject" },
    );
    h.round(
      { offer: { refundUsd: 900, serviceCreditUsd: 450 }, response: "reject" },
      { offer: { refundUsd: 100, serviceCreditUsd: 50 }, response: "reject" },
    );
    assert.equal(h.state.status, "DETERMINATION");
    h.send({
      type: "SET_DETERMINATION_REFERENCE",
      actor: "system",
      terms: declaredReferenceTerms([REFUND, CREDIT], { claimant: cPriv, respondent: rPriv }),
    });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 600, serviceCreditUsd: 300 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 500, serviceCreditUsd: 250 } });
    assert.equal(h.state.outcome?.kind, "SETTLED");
    assert.equal(h.state.outcome?.method, "FINAL_OFFER_DETERMINATION");
    const observedRef = h.state.determination!.reference!;

    const validOpening = {
      disputeId: "dsp_test",
      issues: [REFUND, CREDIT],
      mode: "keyed" as const,
      proposalKeyOrSalt: proposalKey,
      proposalKeyCommitment: expectedKeyCommit,
      declared: {
        claimant: {
          private: cPriv,
          partySalt: cView.bargaining.yourDeclaredVerification.partySalt,
          commitment: cView.bargaining.yourDeclaredVerification.commitment,
        },
        respondent: {
          private: rPriv,
          partySalt: rView.bargaining.yourDeclaredVerification.partySalt,
          commitment: rView.bargaining.yourDeclaredVerification.commitment,
        },
      },
      observedProposals: [{ round: 2, views: { claimant: cProposal, respondent: rProposal } }],
      observedDeterminationReference: observedRef,
    };

    const verified = verifyProposalOpening(validOpening);
    assert.equal(verified.ok, true);
    if (verified.ok) {
      assert.ok(verified.alpha >= 0.3 && verified.alpha <= 0.7);
      assert.equal(verified.expectedProposal.settles, true);
    }

    // Tamper checks
    assert.equal(verifyProposalOpening({ ...validOpening, proposalKeyOrSalt: "0".repeat(64) }).ok, false);
    assert.equal(
      verifyProposalOpening({
        ...validOpening,
        declared: {
          ...validOpening.declared,
          claimant: { ...validOpening.declared.claimant, partySalt: "f".repeat(64) },
        },
      }).ok,
      false,
    );
    assert.equal(
      verifyProposalOpening({
        ...validOpening,
        declared: {
          ...validOpening.declared,
          respondent: {
            ...validOpening.declared.respondent,
            private: { ...rPriv, walkaway: { refundUsd: 640, serviceCreditUsd: 350 } },
          },
        },
      }).ok,
      false,
    );
    assert.equal(
      verifyProposalOpening({
        ...validOpening,
        observedProposals: [{ round: 2, views: { claimant: { refundUsd: cProposal.refundUsd + 10, serviceCreditUsd: cProposal.serviceCreditUsd } } }],
      }).ok,
      false,
    );
    assert.equal(
      verifyProposalOpening({
        ...validOpening,
        observedDeterminationReference: { refundUsd: observedRef.refundUsd + 10, serviceCreditUsd: observedRef.serviceCreditUsd },
      }).ok,
      false,
    );
  });

  it("verifies unkeyed ('salted') mode via derived proposalSalt (never raw audit.salt) and binds expectedIssuesHash (M8, D75, SEC3-5)", () => {
    const h = new Harness().toBargaining();
    // Claimant demands >= 800, respondent refuses > 200 -> no feasible overlap zone
    h.round({ offer: { refundUsd: 950 }, private: single(800) }, { offer: { refundUsd: 50 }, private: single(200) });
    const cView = viewFor(h.state, "claimant");
    const rView = viewFor(h.state, "respondent");
    const proposalSalt = deriveProposalSalt(SALT, "dsp_test");
    const confirmedIssuesHash = issuesHash([REFUND]);

    // Raw master audit.salt must NEVER match proposalKeyCommitment or verify in salted mode (M8)
    const rawSaltAttempt = verifyProposalOpening({
      disputeId: "dsp_test",
      issues: [REFUND],
      expectedIssuesHash: confirmedIssuesHash,
      mode: "salted",
      proposalKeyOrSalt: SALT,
      proposalKeyCommitment: h.state.proposalKeyCommitment!,
      declared: {
        claimant: {
          private: single(800),
          partySalt: cView.bargaining!.yourDeclaredVerification!.partySalt,
          commitment: cView.bargaining!.yourDeclaredVerification!.commitment,
        },
        respondent: {
          private: single(200),
          partySalt: rView.bargaining!.yourDeclaredVerification!.partySalt,
          commitment: rView.bargaining!.yourDeclaredVerification!.commitment,
        },
      },
    });
    assert.equal(rawSaltAttempt.ok, false);

    const baseOpening = {
      disputeId: "dsp_test",
      issues: [REFUND],
      expectedIssuesHash: confirmedIssuesHash,
      mode: "salted" as const,
      proposalKeyOrSalt: proposalSalt,
      proposalKeyCommitment: h.state.proposalKeyCommitment!,
      declared: {
        claimant: {
          private: single(800),
          partySalt: cView.bargaining!.yourDeclaredVerification!.partySalt,
          commitment: cView.bargaining!.yourDeclaredVerification!.commitment,
        },
        respondent: {
          private: single(200),
          partySalt: rView.bargaining!.yourDeclaredVerification!.partySalt,
          commitment: rView.bargaining!.yourDeclaredVerification!.commitment,
        },
      },
      observedProposals: [
        {
          round: 2,
          views: {
            claimant: cView.bargaining!.openProposal!.terms,
            respondent: rView.bargaining!.openProposal!.terms,
          },
        },
      ],
    };

    const res = verifyProposalOpening(baseOpening);
    assert.equal(res.ok, true);
    if (res.ok) {
      assert.equal(res.expectedProposal.settles, false);
    }

    // Mismatched expectedIssuesHash must reject even if issues pass grid validation (Low)
    const badIssuesHash = verifyProposalOpening({
      ...baseOpening,
      issues: [{ ...REFUND, label: "Tampered label" }],
    });
    assert.equal(badIssuesHash.ok, false);
  });

  it("builds RFC 6962 checkpoint Merkle trees and verifies inclusion across odd/even sizes (SEC3-5, DISC-12)", () => {
    const empty = buildCheckpointMerkleTree([]);
    assert.equal(empty.merkleRoot, EMPTY_MERKLE_ROOT);
    assert.equal(empty.leafCount, 0);
    assert.equal(empty.proofFor("dsp_missing"), null);

    for (const count of [1, 2, 3, 5, 17]) {
      const leaves: CheckpointLeafInput[] = Array.from({ length: count }, (_, idx) => ({
        disputeId: `dsp_${String(count - idx).padStart(3, "0")}`, // intentionally reverse-ordered
        status: idx % 2 === 0 ? "HONORED" : "BARGAINING",
        auditSeq: idx + 1,
        auditHead: sha256Hex(`head-${count}-${idx}`),
        outcomeHash: idx % 2 === 0 ? sha256Hex(`outcome-${count}-${idx}`) : null,
      }));
      const tree = buildCheckpointMerkleTree(leaves);
      assert.equal(tree.leafCount, count);
      assert.match(tree.merkleRoot, /^[a-f0-9]{64}$/);
      assert.equal(tree.proofFor("dsp_nonexistent"), null);

      for (const leaf of leaves) {
        const proof = tree.proofFor(leaf.disputeId);
        assert.ok(proof, `proof generated for ${leaf.disputeId}`);
        assert.equal(verifyCheckpointInclusion(leaf, proof, tree.merkleRoot), true);

        // Tamper leaf auditHead -> rejected
        assert.equal(
          verifyCheckpointInclusion({ ...leaf, auditHead: "0".repeat(64) }, proof, tree.merkleRoot),
          false,
        );
        // Tamper expected root -> rejected
        assert.equal(verifyCheckpointInclusion(leaf, proof, "f".repeat(64)), false);
        // Invalid totalLeaves / out-of-bounds leafIndex / wrong leafIndex parity -> rejected
        assert.equal(verifyCheckpointInclusion(leaf, { ...proof, totalLeaves: 0 }, tree.merkleRoot), false);
        assert.equal(verifyCheckpointInclusion(leaf, { ...proof, leafIndex: count }, tree.merkleRoot), false);
        if (count > 1) {
          const flippedIndex = proof.leafIndex === 0 ? 1 : 0;
          assert.equal(verifyCheckpointInclusion(leaf, { ...proof, leafIndex: flippedIndex }, tree.merkleRoot), false);
        }
        if (proof.siblings.length > 0) {
          const badSiblings = proof.siblings.map((s, i) => (i === 0 ? { ...s, hash: "e".repeat(64) } : s));
          assert.equal(verifyCheckpointInclusion(leaf, { ...proof, siblings: badSiblings }, tree.merkleRoot), false);
        }
      }
    }

    assert.throws(
      () =>
        buildCheckpointMerkleTree([
          { disputeId: "dsp_dup", status: "HONORED", auditSeq: 1, auditHead: "a".repeat(64), outcomeHash: null },
          { disputeId: "dsp_dup", status: "HONORED", auditSeq: 2, auditHead: "b".repeat(64), outcomeHash: null },
        ]),
      /duplicate disputeId/,
    );
  });

  it("encodes and decodes 44-byte Base L2 checkpoint anchor calldata deterministically (SEC3-5, DISC-12)", () => {
    const root = sha256Hex("checkpoint-root-42");
    const calldata = encodeBaseAnchorCalldata(42, root);
    // 0x + 88 hex chars = 44 bytes (4B magic + 8B seq + 32B merkleRoot)
    assert.equal(calldata.length, 2 + 88);
    assert.ok(calldata.startsWith("0x414d4350"));
    assert.deepEqual(decodeBaseAnchorCalldata(calldata), { checkpointSeq: 42, merkleRoot: root });
    assert.deepEqual(decodeBaseAnchorCalldata(calldata.toUpperCase().replace(/^0X/, "0x")), {
      checkpointSeq: 42,
      merkleRoot: root,
    });

    assert.throws(() => encodeBaseAnchorCalldata(0, root));
    assert.throws(() => encodeBaseAnchorCalldata(1, "not-a-sha256"));
    assert.equal(decodeBaseAnchorCalldata("0xdeadbeef"), null);
    assert.equal(decodeBaseAnchorCalldata(`0x414d4350${"0".repeat(16)}${root}`), null);

    // Safe-integer boundary checks (1, 2^53 - 1, 2^53, negative, non-integer)
    const minCalldata = encodeBaseAnchorCalldata(1, root);
    assert.deepEqual(decodeBaseAnchorCalldata(minCalldata), { checkpointSeq: 1, merkleRoot: root });
    const maxSafe = Number.MAX_SAFE_INTEGER;
    const maxCalldata = encodeBaseAnchorCalldata(maxSafe, root);
    assert.deepEqual(decodeBaseAnchorCalldata(maxCalldata), { checkpointSeq: maxSafe, merkleRoot: root });
    assert.throws(() => encodeBaseAnchorCalldata(maxSafe + 1, root));
    assert.throws(() => encodeBaseAnchorCalldata(-1, root));
    assert.throws(() => encodeBaseAnchorCalldata(1.5, root));
    // 2^53 = 0x0020000000000000 exceeds JS MAX_SAFE_INTEGER and must decode to null
    assert.equal(decodeBaseAnchorCalldata(`0x414d43500020000000000000${root}`), null);
  });

  it("maintains consistent outcomeHash across zero-obligor SETTLEMENT_IMPROVED, HONORED, and BREACH_REPORTED (M7)", () => {
    const PENALTY: Issue = {
      id: "penaltyUsd",
      label: "Cancellation penalty",
      unit: "USD",
      min: 0,
      max: 1000,
      step: 10,
      claimantPrefers: "lower",
      obligor: "claimant",
    };
    const h = new Harness({ issues: [REFUND, PENALTY] }).toBargaining();
    const cPriv: PrivateInputs = {
      weights: { refundUsd: 0.2, penaltyUsd: 0.8 },
      walkaway: { refundUsd: 0, penaltyUsd: 600 },
    };
    const rPriv: PrivateInputs = {
      weights: { refundUsd: 0.8, penaltyUsd: 0.2 },
      walkaway: { refundUsd: 600, penaltyUsd: 0 },
    };
    // Round 1 settles at mutual wash (500, 500) -> both have obligations, Pareto improvement is mutual release (0, 0)
    h.round(
      { offer: { refundUsd: 500, penaltyUsd: 500 }, private: cPriv },
      { offer: { refundUsd: 500, penaltyUsd: 500 }, private: rPriv },
    );
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.deepEqual(h.state.execution?.improvement?.terms, { refundUsd: 0, penaltyUsd: 0 });

    h.send({ type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" });
    h.send({ type: "RESPOND_IMPROVEMENT", actor: "respondent", response: "accept" });
    assert.equal(h.state.status, "HONORED");
    assert.deepEqual(h.state.execution?.obligors, []);

    const doc = buildSettlementInstruction(h.state);
    const improvedEv = h.events.find((e) => e.type === "SETTLEMENT_IMPROVED")!;
    const honoredEv = h.events.find((e) => e.type === "HONORED")!;
    assert.equal(improvedEv.data.outcomeHash, doc.outcomeHash);
    assert.equal(honoredEv.data.outcomeHash, doc.outcomeHash);

    // Breach path also commits final BREACH_REPORTED outcomeHash in the terminal event
    const b = new Harness().toBargaining();
    b.round({ offer: { refundUsd: 400 }, private: single(300) }, { offer: { refundUsd: 400 }, private: single(500) });
    b.expire();
    assert.equal(b.state.status, "BREACH_REPORTED");
    const breachEv = b.events.find((e) => e.type === "BREACH_REPORTED")!;
    assert.equal(breachEv.data.outcomeHash, buildSettlementInstruction(b.state).outcomeHash);
  });

  it("matches hand-computed Merkle known-answer vector, permutation invariance, side-flip rejection, and totalLeaves binding (M3b)", () => {
    const mk = (id: string, seq: number): CheckpointLeafInput => ({
      disputeId: id,
      status: "HONORED",
      auditSeq: seq,
      auditHead: sha256Hex(`head:${id}`),
      outcomeHash: sha256Hex(`out:${id}`),
    });
    const l0 = mk("dsp_a", 1);
    const l1 = mk("dsp_b", 2);
    const l2 = mk("dsp_c", 3);
    const l3 = mk("dsp_d", 4);
    const l4 = mk("dsp_e", 5);

    // Known-answer 5-leaf tree: split k=4 -> left=((h0,h1),(h2,h3)), right=h4
    const h0 = sha256Hex(CHECKPOINT_LEAF_DOMAIN + canonicalJson(l0));
    const h1 = sha256Hex(CHECKPOINT_LEAF_DOMAIN + canonicalJson(l1));
    const h2 = sha256Hex(CHECKPOINT_LEAF_DOMAIN + canonicalJson(l2));
    const h3 = sha256Hex(CHECKPOINT_LEAF_DOMAIN + canonicalJson(l3));
    const h4 = sha256Hex(CHECKPOINT_LEAF_DOMAIN + canonicalJson(l4));
    const n01 = sha256Hex(`${CHECKPOINT_NODE_DOMAIN}${h0}\n${h1}`);
    const n23 = sha256Hex(`${CHECKPOINT_NODE_DOMAIN}${h2}\n${h3}`);
    const n0123 = sha256Hex(`${CHECKPOINT_NODE_DOMAIN}${n01}\n${n23}`);
    const expectedRoot5 = sha256Hex(`${CHECKPOINT_NODE_DOMAIN}${n0123}\n${h4}`);
    assert.equal(h0, checkpointLeafHash(l0));
    assert.equal(n01, checkpointNodeHash(h0, h1));

    const treeA = buildCheckpointMerkleTree([l4, l1, l3, l0, l2]);
    const treeB = buildCheckpointMerkleTree([l0, l1, l2, l3, l4]);
    assert.equal(treeA.merkleRoot, expectedRoot5);
    assert.equal(treeB.merkleRoot, expectedRoot5);

    // Sibling side-flip tamper, extra sibling, and missing sibling must fail
    const p2 = treeA.proofFor("dsp_c")!;
    assert.equal(
      verifyCheckpointInclusion(
        l2,
        {
          ...p2,
          siblings: p2.siblings.map((s, idx) => (idx === 0 ? { ...s, side: s.side === "left" ? "right" : "left" } : s)),
        },
        expectedRoot5,
      ),
      false,
    );
    assert.equal(
      verifyCheckpointInclusion(l2, { ...p2, siblings: p2.siblings.slice(0, -1) }, expectedRoot5),
      false,
    );
    assert.equal(
      verifyCheckpointInclusion(
        l2,
        { ...p2, siblings: [...p2.siblings, { side: "right", hash: h4 }] },
        expectedRoot5,
      ),
      false,
    );

    // M3(b): leaf idx=4 in n=5 has a single left sibling (n0123), which looks topologically like idx=1 in n=2
    // unless expectedTotalLeaves binds proof.totalLeaves to the signed checkpoint's disputeCount.
    const p4 = treeA.proofFor("dsp_e")!;
    assert.equal(p4.siblings.length, 1);
    const swapped = { ...p4, totalLeaves: 2, leafIndex: 1 };
    assert.equal(
      (verifyCheckpointInclusion as (l: CheckpointLeafInput, p: typeof swapped, r: string, o?: { expectedTotalLeaves?: number }) => boolean)(
        l4,
        swapped,
        expectedRoot5,
        { expectedTotalLeaves: 5 },
      ),
      false,
    );
  });

  it("returns false / ok:false without throwing on malformed verifier inputs and omits unanchored legacy commitments (Low)", () => {
    assert.equal(verifyCheckpointInclusion(null as never, null as never, ""), false);
    assert.equal(verifyCheckpointInclusion({} as never, { totalLeaves: 1, leafIndex: 0, siblings: [null] } as never, "0".repeat(64)), false);
    assert.equal(verifyProposalOpening(null as never).ok, false);
    assert.equal(verifyProposalOpening({} as never).ok, false);

    // Legacy state before Phase 4 without anchored declaredCommitments must NOT synthesize a fake commitment
    const h = new Harness().toBargaining();
    h.round({ offer: { refundUsd: 800 }, private: single(600) }, { offer: { refundUsd: 200 }, private: single(400) });
    const legacyState = structuredClone(h.state);
    delete legacyState.declaredCommitments;
    const legacyView = viewFor(legacyState, "claimant");
    assert.equal(legacyView.bargaining?.yourDeclaredVerification, null);
  });
});
