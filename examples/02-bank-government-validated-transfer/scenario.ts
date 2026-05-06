/**
 * Example 2 — Bank wire transfer gated by government-signed approval.
 *
 * Run: npm run example:bank
 */
import { LatticeGateway } from '../../core/gateway';
import { WhitePolicy } from '../../core/policy';
import { LatticeCA, SignedCert } from '../../core/ca';
import { AgentCert, CapabilityToken, DelegationGrant, IntentAnchor, WhiteCertificate } from '../../core/types';
import { generateKeyPair, signData, verifySignature } from '../../core/identity';

const GOV_APPROVAL_SCHEMA = 'gov.transfer.approval.v1';

interface GovApprovalPayload {
  schema: typeof GOV_APPROVAL_SCHEMA;
  intent_id: string;
  beneficiary_id: string;
  max_amount: string;
  currency: string;
  valid_until: string;
}

function buildApprovalDocument(p: GovApprovalPayload): string {
  return JSON.stringify(p);
}

function signGovernmentApproval(govCa: LatticeCA, payload: GovApprovalPayload): string {
  return signData(buildApprovalDocument(payload), govCa.privateKey);
}

function verifyGovernmentApproval(govPublicKey: string, payload: GovApprovalPayload, signature: string): boolean {
  return verifySignature(buildApprovalDocument(payload), signature, govPublicKey);
}

function assertGovernmentApprovedTransfer(opts: {
  govPublicKey: string;
  approval: GovApprovalPayload;
  signature: string;
  intent: IntentAnchor;
  maxAmount: string;
}) {
  if (new Date(opts.approval.valid_until) <= new Date()) {
    throw new Error('Government approval expired');
  }
  if (opts.approval.intent_id !== opts.intent.intent_id) {
    throw new Error('Government approval intent_id does not match client intent');
  }
  if (opts.approval.max_amount !== opts.maxAmount) {
    throw new Error('Government approval max_amount does not match requested transfer cap');
  }
  if (!verifyGovernmentApproval(opts.govPublicKey, opts.approval, opts.signature)) {
    throw new Error('Invalid government signature on transfer approval');
  }
}

async function main() {
  const govCa = new LatticeCA('gov:ux:treasury-oversight');
  const bankCa = new LatticeCA('org:acme-bank:enterprise-ca');

  const bankAgentKeys = generateKeyPair();
  const signedBankAgent: SignedCert<AgentCert> = bankCa.issueAgentCert({
    agent_id: 'agent:acme-bank:wire-bot',
    owner_org: 'org:acme-bank',
    agent_type: 'payments',
    version: '1.0',
    public_key: bankAgentKeys.publicKey,
    allowed_capability_classes: ['money:execute'],
    forbidden_capability_classes: ['code:deploy'],
    expires_in_days: 30,
  });

  const policy = new WhitePolicy();
  policy.grantCapability({
    agent_id: signedBankAgent.cert.agent_id,
    tool_id: 'bank.transfer.wire',
    capability_class: 'money:execute',
    granted_by: 'human:bank-approver',
    expires_in_hours: 8,
  });

  const gatewayKeys = generateKeyPair();
  const gateway = new LatticeGateway('gw:acme-bank:primary', gatewayKeys.privateKey);
  gateway.setPolicy(policy);
  gateway.registerAgent(signedBankAgent, bankCa.publicKey);

  const delegation: DelegationGrant = {
    human_subject: 'human:customer-4242',
    agent_id: signedBankAgent.cert.agent_id,
    delegation: {
      allowed_actions: ['bank.transfer.wire'],
      forbidden_actions: [],
      max_amount: '5000',
      expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
    },
  };

  const intent: IntentAnchor = {
    intent_id: 'intent:wire-rent-march',
    human_or_org: 'human:customer-4242',
    goal: 'Pay March rent via wire',
    allowed_actions: ['bank.transfer.wire'],
    forbidden_actions: [],
    budget: '5000',
    expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
  };

  const capability: CapabilityToken = {
    capability_id: 'cap:wire-once',
    subject: signedBankAgent.cert.agent_id,
    delegated_by: 'human:customer-4242',
    allowed_tool: 'bank.transfer.wire',
    constraints: {
      max_amount: '5000',
      requires_human_approval: false,
      expires_at: new Date(Date.now() + 8 * 3_600_000).toISOString(),
    },
  };

  const approvalPayload: GovApprovalPayload = {
    schema: GOV_APPROVAL_SCHEMA,
    intent_id: intent.intent_id,
    beneficiary_id: 'acct:landlord:987',
    max_amount: '5000',
    currency: 'USD',
    valid_until: new Date(Date.now() + 2 * 3_600_000).toISOString(),
  };
  const govSig = signGovernmentApproval(govCa, approvalPayload);

  assertGovernmentApprovedTransfer({
    govPublicKey: govCa.publicKey,
    approval: approvalPayload,
    signature: govSig,
    intent,
    maxAmount: '5000',
  });

  const call = {
    agent_id: signedBankAgent.cert.agent_id,
    delegation,
    intent,
    capability,
    capability_class: 'money:execute' as const,
    tool_id: 'bank.transfer.wire',
    action_type: 'wire_transfer',
    action_parameters: { to: 'acct:landlord:987', amount: '4800', currency: 'USD' },
    runtime_cert_hash: 'runtime:hash:bank-sandbox',
  };

  const callActionTimestamp = new Date().toISOString();
  const saae = await gateway.mediateToolCall({
    ...call,
    action_timestamp: callActionTimestamp,
    agent_signature: signData(JSON.stringify({ agent_id: call.agent_id, tool_id: call.tool_id, action_type: call.action_type, action_parameters: call.action_parameters, capability_id: capability.capability_id, timestamp: callActionTimestamp }), bankAgentKeys.privateKey),
  });

  console.log('Government approval: signature valid against registered gov CA public key.');
  console.log(
    `Gateway policy decision: ${saae.policy.decision} (action_id=${saae.action_id}) — note: MVP WhitePolicy escalates money:execute (risk 5) to require_human_approval even when grants exist; gov attestation is enforced in code before this call.`,
  );

  // Tampered approval must fail before gateway
  const tampered: GovApprovalPayload = { ...approvalPayload, max_amount: '500000' };
  const badSig = signGovernmentApproval(govCa, tampered);
  try {
    assertGovernmentApprovedTransfer({
      govPublicKey: govCa.publicKey,
      approval: tampered,
      signature: badSig,
      intent,
      maxAmount: '5000',
    });
    throw new Error('expected mismatch on max_amount');
  } catch (e: any) {
    console.log(`\nTampered approval correctly rejected: ${e.message}`);
  }

  if (!bankCa.verifyCert(signedBankAgent as SignedCert<WhiteCertificate>)) {
    throw new Error('bank agent cert should verify under bank CA');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
