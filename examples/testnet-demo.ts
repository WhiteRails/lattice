/**
 * Lattice Local Testnet Demo v0
 *
 * Implements the full flow from whitepaper §20:
 *
 *   white-ca issue-org
 *   white-ca issue-agent
 *   white-ca issue-service
 *   white-policy grant capability
 *   white-agent call service
 *   white-gateway enforce
 *   white-log append
 *   white-dashboard inspect
 *   white-ca revoke-agent
 *   white-agent call again → blocked
 *
 * Run with: npx ts-node examples/testnet-demo.ts
 */

import { LatticeCA } from '../core/ca';
import { LatticeGateway, toolCallSignaturePayload } from '../core/gateway';
import { LatticeRegistry } from '../core/registry';
import { RevocationNetwork } from '../core/revocation';
import { PowerAccumulationTracker } from '../core/pas';
import { WhitePolicy } from '../core/policy';
import { LatticeLog } from '../core/log';
import { generateKeyPair, signData } from '../core/identity';
import { hashObject } from '../core/envelope';
import { DelegationGrant, IntentAnchor, CapabilityToken } from '../core/types';

// ─── Helpers ─────────────────────────────────────────────────────────────────

const dim  = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const grn  = (s: string) => `\x1b[32m${s}\x1b[0m`;
const red  = (s: string) => `\x1b[31m${s}\x1b[0m`;
const yel  = (s: string) => `\x1b[33m${s}\x1b[0m`;
const blu  = (s: string) => `\x1b[34m${s}\x1b[0m`;

function step(n: number, label: string) {
  console.log(`\n${bold(blu(`▶ Step ${n}:`))} ${bold(label)}`);
}

function ok(msg: string)   { console.log(`  ${grn('✓')} ${msg}`); }
function fail(msg: string) { console.log(`  ${red('✗')} ${msg}`); }
function info(msg: string) { console.log(`  ${dim(msg)}`); }

async function run() {
  console.log(bold('\n╔══════════════════════════════════════════╗'));
  console.log(bold('║   Lattice Local Testnet v0              ║'));
  console.log(bold('╚══════════════════════════════════════════╝'));

  // ── Step 1: Spin up CA ───────────────────────────────────────────────────
  step(1, 'white-ca issue-org / issue-agent / issue-service');

  const ca = new LatticeCA('ca.lattice.local');
  info(`CA created: ${ca.id}`);

  const orgCert = ca.issueOrgCert({ org_id: 'org:acme', expires_in_days: 365 });
  ok(`OrgCert issued  → ${orgCert.cert.id}`);

  const agentKeys = generateKeyPair();
  const agentSigned = ca.issueAgentCert({
    agent_id: 'agent:acme:support-v1',
    owner_org: 'org:acme',
    agent_type: 'support',
    version: '1.0',
    public_key: agentKeys.publicKey,
    allowed_capability_classes: ['message:single', 'message:mass'],
    forbidden_capability_classes: ['money:execute', 'code:deploy'],
    expires_in_days: 30,
  });
  ok(`AgentCert issued → ${agentSigned.cert.agent_id}`);

  const serviceCert = ca.issueServiceCert({ service_id: 'svc:gmail', expires_in_days: 365 });
  ok(`ServiceCert issued → ${serviceCert.cert.id}`);

  const gatewaySigned = ca.issueGatewayCert({ gateway_id: 'gw:acme:primary' });
  ok(`GatewayCert issued → ${gatewaySigned.cert.id}`);

  // ── Step 1.5: LatticeLog ───────────────────────────────────────────────────
  const logKeys = generateKeyPair();
  const log = new LatticeLog('log.lattice.local', logKeys.privateKey);

  // ── Step 2: Registry ──────────────────────────────────────────────────────
  step(2, 'white-registry register (Federated)');

  const registry = new LatticeRegistry('registry.lattice.local', log);
  const agentName = registry.register({
    name: 'support-agent.acme.lattice',
    subject_id: 'did:traceveil:org:acme:agent:support-v1',
    public_key: agentKeys.publicKey,
    signing_key_id: 'key_acme_support_signing_v1',
    service_cert: agentSigned.cert.id,
    gateway_endpoints: ['quic://gateway.acme.internal:4433'],
    issuer: orgCert.cert.id,
    accepted_agent_issuers: [orgCert.cert.id],
    policy_profile: 'support-agent-v1',
    linked_org_id: 'org:acme',
  });

  const svcName = registry.register({
    name: 'gmail-gateway.cloud.lattice',
    subject_id: 'did:traceveil:svc:gmail-gateway',
    public_key: generateKeyPair().publicKey,
    signing_key_id: 'key_gmail_gateway_initial',
    service_cert: serviceCert.cert.id,
    gateway_endpoints: ['quic://gmail.gateway.lattice:4433'],
    issuer: ca.id,
    accepted_agent_issuers: [orgCert.cert.id],
  });

  ok(`Agent registered → ${agentName}`);
  ok(`Service registered → ${svcName}`);

  const rot = generateKeyPair();
  const overlapUntil = new Date(Date.now() + 7 * 86400000).toISOString();
  registry.rotateSigningKey({
    name: 'gmail-gateway.cloud.lattice',
    old_key_id: 'key_gmail_gateway_initial',
    new_key_id: 'key_gmail_gateway_q2',
    new_public_key: rot.publicKey,
    effective_at: new Date().toISOString(),
    old_key_valid_until: overlapUntil,
    signed_by: ['key_gmail_gateway_initial', 'recovery_key_acme'],
  });
  ok('KEY_ROTATION logged for gmail-gateway.cloud.lattice (overlap window set)');

  // ── Step 3: Policy grants ─────────────────────────────────────────────────
  step(3, 'white-policy grant capability');

  const policy = new WhitePolicy();
  const draftGrant = policy.grantCapability({
    agent_id: 'agent:acme:support-v1',
    tool_id: 'gmail.draft_email',
    capability_class: 'message:single',
    granted_by: 'human:alice',
    expires_in_hours: 8,
  });
  ok(`Grant issued → ${draftGrant.grant_id}  (tool: gmail.draft_email)`);

  // Note: no send grant yet
  info('  gmail.send_email NOT granted yet');

  // ── Step 4: Infrastructure ────────────────────────────────────────────────
  step(4, 'Initialise gateway, log, PAS tracker');

  const revocation = new RevocationNetwork();
  const pasTracker = new PowerAccumulationTracker();
  const gatewayKeys = generateKeyPair();
  const gateway = new LatticeGateway('gw:acme:primary', gatewayKeys.privateKey);
  gateway.setRevocationNetwork(revocation);
  gateway.setPASTracker(pasTracker);
  gateway.setPolicy(policy);
  gateway.setLog(log);

  gateway.registerAgent(agentSigned, ca.publicKey);
  ok('Gateway ready with policy + log + PAS tracker');

  // ── Step 5: Shared request objects ────────────────────────────────────────
  const delegation: DelegationGrant = {
    human_subject: 'human:alice',
    agent_id: 'agent:acme:support-v1',
    delegation: {
      allowed_actions: ['gmail.draft_email'],
      forbidden_actions: ['gmail.send_email'],
      expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
    },
  };

  const intent: IntentAnchor = {
    intent_id: 'intent:reply-ticket-42',
    human_or_org: 'human:alice',
    goal: 'Reply to support ticket #42',
    allowed_actions: ['gmail.draft_email'],
    forbidden_actions: [],
    expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
  };

  const draftCapToken: CapabilityToken = {
    capability_id: 'cap:draft',
    subject: 'agent:acme:support-v1',
    delegated_by: 'human:alice',
    allowed_tool: 'gmail.draft_email',
    constraints: {
      requires_human_approval: false,
      expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
    },
  };

  // ── Step 6: Agent calls gmail.draft_email ─────────────────────────────────
  step(5, 'white-agent call gmail.draft_email  →  expected: allow');

  const draftCall = {
    agent_id: 'agent:acme:support-v1' as const,
    delegation,
    intent,
    capability: draftCapToken,
    capability_class: 'message:single' as const,
    tool_id: 'gmail.draft_email',
    action_type: 'draft_email',
    action_parameters: { to: 'customer@example.com', subject: 'Re: Ticket #42', body: '…' },
    runtime_cert_hash: 'runtime:hash:abc',
  };
  const draftSAAE = await gateway.mediateToolCall({
    ...draftCall,
    agent_signature: signData(toolCallSignaturePayload(draftCall), agentKeys.privateKey),
  });
  ok(`Decision: ${grn(draftSAAE.policy.decision)}  action_id=${draftSAAE.action_id}`);

  // ── Step 7: Agent tries gmail.send_email (no grant) ───────────────────────
  step(6, 'white-agent call gmail.send_email (no grant)  →  expected: deny');

  const sendCapToken: CapabilityToken = {
    capability_id: 'cap:send',
    subject: 'agent:acme:support-v1',
    delegated_by: 'human:alice',
    allowed_tool: 'gmail.send_email',
    constraints: {
      requires_human_approval: false,
      expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
    },
  };

  let sendDecision = 'unknown';
  try {
    const sendCall = {
      agent_id: 'agent:acme:support-v1' as const,
      delegation,
      intent,
      capability: sendCapToken,
      capability_class: 'message:single' as const,
      tool_id: 'gmail.send_email',
      action_type: 'send_email',
      action_parameters: { to: 'customer@example.com' },
      runtime_cert_hash: 'runtime:hash:abc',
    };
    await gateway.mediateToolCall({
      ...sendCall,
      agent_signature: signData(toolCallSignaturePayload(sendCall), agentKeys.privateKey),
    });
  } catch (e: any) {
    // capability mismatch throws before policy check in MVP
    sendDecision = 'blocked (capability mismatch)';
  }

  // Run policy eval directly so we can also show the deny path
  const policyResult = policy.evaluate({
    agent_id: 'agent:acme:support-v1',
    tool_id: 'gmail.send_email',
    capability_class: 'message:single',
    pas_score: 0,
  });
  ok(`Policy decision: ${red(policyResult.decision)}  reason: ${policyResult.reason}`);

  // ── Step 8: PAS escalation ────────────────────────────────────────────────
  step(7, 'PAS escalation  →  expected: require_human_approval');

  pasTracker.recordAction('agent:acme:support-v1', { agent_replication_attempted: 3 });
  const pasScore = pasTracker.getScore('agent:acme:support-v1');
  info(`PAS score after replication attempts: ${pasScore.score}`);

  const pasCall = {
    agent_id: 'agent:acme:support-v1' as const,
    delegation,
    intent,
    capability: draftCapToken,
    capability_class: 'message:single' as const,
    tool_id: 'gmail.draft_email',
    action_type: 'draft_email',
    action_parameters: { to: 'customer@example.com' },
    runtime_cert_hash: 'runtime:hash:abc',
    pas_updates: {},
  };
  const pasSAAE = await gateway.mediateToolCall({
    ...pasCall,
    agent_signature: signData(toolCallSignaturePayload(pasCall), agentKeys.privateKey),
  });
  ok(`Decision: ${yel(pasSAAE.policy.decision)}`);

  // ── Step 9: Log & batch ───────────────────────────────────────────────────
  step(8, 'white-log append / compute batch');

  const entries = log.getEntries();
  ok(`${entries.length} entries in log`);

  const batch = log.computeBatch();
  ok(`Batch sealed  id=${batch.batch_id}  actions=${batch.action_count}  root=${batch.merkle_root.slice(0, 16)}…`);

  const proof = log.getProof(draftSAAE.action_id);
  if (proof) {
    const valid = log.verifyProof(proof);
    ok(`Merkle proof for ${draftSAAE.action_id.slice(0, 12)}…  valid=${grn(String(valid))}`);
  }

  // ── Step 10: Dashboard inspect ────────────────────────────────────────────
  step(9, 'white-dashboard inspect');

  console.log(`\n  ${'─'.repeat(52)}`);
  console.log(`  ${bold('Agent')}        agent:acme:support-v1`);
  console.log(`  ${bold('Log entries')}  ${entries.length}`);
  console.log(`  ${bold('Batches')}      ${log.getBatches().length}`);
  console.log(`  ${bold('PAS score')}    ${pasTracker.getScore('agent:acme:support-v1').score}`);
  console.log(`  ${bold('Grants')}       ${policy.getGrants().length}`);
  for (const e of entries) {
    if (e.event_type) {
      console.log(`  ${blu('ℹ')} [${e.index}] Registry: ${e.target_name} → ${e.event_type}`);
    } else {
      const icon = e.policy_decision === 'allow' ? grn('✓') : yel('⚠');
      console.log(`  ${icon} [${e.index}] Action: ${e.tool_id}  →  ${e.policy_decision}`);
    }
  }
  console.log(`  ${'─'.repeat(52)}`);

  // ── Step 11: Revoke agent, try again ─────────────────────────────────────
  step(10, 'white-ca revoke-agent  →  next call blocked');

  ca.revoke(agentSigned.cert.id, 'test_revocation', revocation);
  ok(`AgentCert revoked: ${agentSigned.cert.id}`);

  let blocked = false;
  try {
    await gateway.mediateToolCall({
      agent_id: 'agent:acme:support-v1',
      agent_signature: 'sig:placeholder',
      delegation,
      intent,
      capability: draftCapToken,
      capability_class: 'message:single',
      tool_id: 'gmail.draft_email',
      action_type: 'draft_email',
      action_parameters: {},
      runtime_cert_hash: 'runtime:hash:abc',
    });
  } catch (e: any) {
    blocked = true;
    ok(`Call blocked: ${red(e.message)}`);
  }

  if (!blocked) fail('Expected call to be blocked after revocation');

  // ── Done ──────────────────────────────────────────────────────────────────
  console.log(`\n${bold(grn('✔ Testnet demo complete.'))}\n`);
}

run().catch(err => {
  console.error(red(`\nFatal: ${err.message}`));
  process.exit(1);
});
