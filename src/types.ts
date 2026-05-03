import { z } from 'zod';

/**
 * Base Certificate schema
 */
export const WhiteCertificateSchema = z.object({
  id: z.string(),
  type: z.string(),
  issuer: z.string(),
  public_key: z.string(),
  issued_at: z.string().datetime(),
  expires_at: z.string().datetime().optional(),
  revocation_endpoint: z.string().url().optional(),
});

export type WhiteCertificate = z.infer<typeof WhiteCertificateSchema>;

/**
 * Agent Certificate schema
 */
export const AgentCertSchema = WhiteCertificateSchema.extend({
  type: z.literal('AgentCert'),
  agent_id: z.string(),
  owner_org: z.string(),
  agent_type: z.string(),
  version: z.string(),
  runtime_requirements: z.array(z.string()).optional(),
  allowed_capability_classes: z.array(z.string()),
  forbidden_capability_classes: z.array(z.string()),
});

export type AgentCert = z.infer<typeof AgentCertSchema>;

/**
 * Delegation Grant schema
 */
export const DelegationGrantSchema = z.object({
  human_subject: z.string(),
  agent_id: z.string(),
  delegation: z.object({
    allowed_actions: z.array(z.string()),
    forbidden_actions: z.array(z.string()),
    max_amount: z.string().optional(),
    expires_at: z.string().datetime(),
  }),
});

export type DelegationGrant = z.infer<typeof DelegationGrantSchema>;

/**
 * Intent Anchor schema
 */
export const IntentAnchorSchema = z.object({
  intent_id: z.string(),
  human_or_org: z.string(),
  goal: z.string(),
  allowed_actions: z.array(z.string()),
  forbidden_actions: z.array(z.string()),
  budget: z.string().optional(),
  expires_at: z.string().datetime(),
});

export type IntentAnchor = z.infer<typeof IntentAnchorSchema>;

/**
 * Capability Token schema
 */
export const CapabilityTokenSchema = z.object({
  capability_id: z.string(),
  subject: z.string(),
  delegated_by: z.string(),
  allowed_tool: z.string(),
  constraints: z.object({
    max_amount: z.string().optional(),
    requires_human_approval: z.boolean(),
    allowed_customers: z.array(z.string()).optional(),
    expires_at: z.string().datetime(),
  }),
});

export type CapabilityToken = z.infer<typeof CapabilityTokenSchema>;

/**
 * Signed Agent Action Envelope (SAAE) schema
 */
export const SAAESchema = z.object({
  schema: z.literal('white-protocol.action-envelope.v0.1'),
  action_id: z.string(),
  timestamp: z.string().datetime(),
  actor: z.object({
    agent_id: z.string(),
    agent_cert_hash: z.string(),
  }),
  authority: z.object({
    org_id: z.string(),
    delegation_hash: z.string(),
    intent_anchor_hash: z.string(),
  }),
  model: z.object({
    provider_cert_hash: z.string().optional(),
    model_cert_hash: z.string().optional(),
  }).optional(),
  runtime: z.object({
    runtime_cert_hash: z.string(),
  }),
  tool: z.object({
    tool_id: z.string(),
    tool_cert_hash: z.string().optional(),
    capability_class: z.string().optional(),
    risk_level: z.number().int().min(0).max(5).optional(),
  }),
  policy: z.object({
    policy_id: z.string().optional(),
    decision: z.enum(['allow', 'deny', 'require_human_approval']),
    risk_level: z.number().int().min(0).max(5).optional(),
    requires_human_approval: z.boolean().optional(),
    approval_id: z.string().optional(),
  }),
  action: z.object({
    type: z.string(),
    target_hash: z.string(),
    parameter_hash: z.string(),
  }),
  evidence: z.object({
    request_hash: z.string().optional(),
    response_hash: z.string().optional(),
    encrypted_bundle_ref: z.string().optional(),
    bundle_hash: z.string().optional(),
  }),
  signatures: z.object({
    agent_signature: z.string(),
    runtime_signature: z.string().optional(),
    gateway_signature: z.string().optional(),
    tool_signature: z.string().optional(),
  }),
});

export type SAAE = z.infer<typeof SAAESchema>;

/**
 * Revocation Record schema
 */
export const RevocationRecordSchema = z.object({
  schema: z.literal('whitenet.revocation.v0.1'),
  target_type: z.string(),
  target_hash: z.string(),
  revoked_by: z.string(),
  reason: z.string(),
  effective_at: z.string().datetime(),
  signature: z.string(),
});

export type RevocationRecord = z.infer<typeof RevocationRecordSchema>;

/**
 * Registry Record schema
 */
export const RegistryRecordSchema = z.object({
  address: z.string(),
  public_key: z.string(),
  certificate_chain: z.array(z.string()),
  issuer: z.string(),
  is_revoked: z.boolean(),
  accepted_capabilities: z.array(z.string()),
  protecting_gateways: z.array(z.string()),
});

export type RegistryRecord = z.infer<typeof RegistryRecordSchema>;

/**
 * Power Accumulation Score schema
 */
export const PASScoreSchema = z.object({
  score: z.number().min(0),
  factors: z.object({
    compute_acquired: z.number().default(0),
    money_accessible: z.number().default(0),
    credentials_created: z.number().default(0),
    infrastructure_modified: z.number().default(0),
    code_deployed: z.number().default(0),
    humans_contacted: z.number().default(0),
    reach_expanded: z.number().default(0),
    identity_multiplied: z.number().default(0),
    persistence_increased: z.number().default(0),
    agent_replication_attempted: z.number().default(0),
    sensitive_data_accessed: z.number().default(0),
  }),
  last_updated: z.string().datetime(),
});

export type PASScore = z.infer<typeof PASScoreSchema>;
