import { z } from 'zod';

// ─────────────────────────────────────────────────────────────────────────────
// Base Certificate
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Certificate Types (§4.1)
// ─────────────────────────────────────────────────────────────────────────────

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

export const OrgCertSchema = WhiteCertificateSchema.extend({
  type: z.literal('OrgCert'),
  org_id: z.string().optional(),
});
export type OrgCert = z.infer<typeof OrgCertSchema>;

export const ModelCertSchema = WhiteCertificateSchema.extend({
  type: z.literal('ModelCert'),
  model_id: z.string(),
  model_family: z.string().optional(),
  provider_cert_id: z.string().optional(),
});
export type ModelCert = z.infer<typeof ModelCertSchema>;

export const ModelProviderCertSchema = WhiteCertificateSchema.extend({
  type: z.literal('ModelProviderCert'),
  provider_name: z.string(),
});
export type ModelProviderCert = z.infer<typeof ModelProviderCertSchema>;

export const HumanDelegationCertSchema = WhiteCertificateSchema.extend({
  type: z.literal('HumanDelegationCert'),
  human_id: z.string(),
  delegated_to_agent: z.string(),
  scope: z.array(z.string()),
});
export type HumanDelegationCert = z.infer<typeof HumanDelegationCertSchema>;

export const AuditorCertSchema = WhiteCertificateSchema.extend({
  type: z.literal('AuditorCert'),
  auditor_id: z.string(),
  authorized_orgs: z.array(z.string()).optional(),
});
export type AuditorCert = z.infer<typeof AuditorCertSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Delegation & Intent
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Revocation (§12)
// ─────────────────────────────────────────────────────────────────────────────

export const RevocationRecordSchema = z.object({
  schema: z.literal('lattice.revocation.v0.1'),
  target_type: z.string(),
  target_hash: z.string(),
  revoked_by: z.string(),
  reason: z.string(),
  effective_at: z.string().datetime(),
  signature: z.string(),
});
export type RevocationRecord = z.infer<typeof RevocationRecordSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Revocation Freshness Proof (§4.3)
// ─────────────────────────────────────────────────────────────────────────────

export const RevocationFreshnessProofSchema = z.object({
  schema: z.literal('lattice.freshness.v0.1'),
  cert_hash: z.string(),
  checked_at: z.string().datetime(),
  not_revoked: z.boolean(),
  checker_id: z.string(),
  max_staleness_ms: z.number(),
  signature: z.string(),
});
export type RevocationFreshnessProof = z.infer<typeof RevocationFreshnessProofSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Registry (§7.6) — federated, name-based
// ─────────────────────────────────────────────────────────────────────────────

export const RegistryRecordSchema = z.object({
  name: z.string(),
  public_key: z.string(),
  service_cert: z.string(),
  gateway_endpoints: z.array(z.string()),
  issuer: z.string(),
  accepted_agent_issuers: z.array(z.string()),
  policy_profile: z.string().optional(),
  registered_at: z.string().datetime(),
  is_revoked: z.boolean(),
});
export type RegistryRecord = z.infer<typeof RegistryRecordSchema>;

/** Transparency log event for registry mutations. */
export const RegistryEventSchema = z.object({
  event: z.enum(['registered', 'key_rotated', 'revoked', 'policy_updated']),
  name: z.string(),
  effective_at: z.string().datetime(),
  new_public_key: z.string().optional(),
  issuer: z.string(),
});
export type RegistryEvent = z.infer<typeof RegistryEventSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Signed Agent Action Envelope / SAAE (§8 Step 7)
// ─────────────────────────────────────────────────────────────────────────────

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
  runtime: z.object({ runtime_cert_hash: z.string() }),
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

// ─────────────────────────────────────────────────────────────────────────────
// Evidence Store (§11)
// ─────────────────────────────────────────────────────────────────────────────

export const EncryptedEvidenceSchema = z.object({
  ref: z.string(),
  action_id: z.string(),
  created_at: z.string().datetime(),
  /** AES-256-GCM ciphertext (hex) */
  ciphertext: z.string(),
  /** GCM auth tag (hex) */
  auth_tag: z.string(),
  /** GCM IV (hex) */
  iv: z.string(),
  /** Map of recipientId → base64(RSA-wrapped AES key) */
  wrapped_keys: z.record(z.string()),
});
export type EncryptedEvidence = z.infer<typeof EncryptedEvidenceSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Human Approval (§8 Step 5)
// ─────────────────────────────────────────────────────────────────────────────

export const ApprovalRequestSchema = z.object({
  request_id: z.string(),
  action_id: z.string(),
  agent_id: z.string(),
  tool_id: z.string(),
  capability_class: z.string(),
  risk_level: z.number(),
  requested_at: z.string().datetime(),
  expires_at: z.string().datetime(),
  status: z.enum(['pending', 'approved', 'denied', 'expired']),
  required_signers: z.array(z.string()).optional(),
  collected_signatures: z.array(z.object({
    signer: z.string(),
    signature: z.string(),
    signed_at: z.string().datetime(),
  })).optional(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Overlay / Circuit Types (§14)
// ─────────────────────────────────────────────────────────────────────────────

export const CircuitCellSchema = z.object({
  circuit_id: z.string(),
  hop: z.number().int(),
  /** Onion-encrypted payload layers; each relay peels one */
  payload: z.string(),
  next_hop_id: z.string().optional(),
  created_at: z.string().datetime(),
});
export type CircuitCell = z.infer<typeof CircuitCellSchema>;

export const OverlayMessageSchema = z.object({
  message_id: z.string(),
  circuit_id: z.string(),
  origin_agent_id: z.string(),
  target_service: z.string(),
  /** JSON-serialised request, encrypted for the gateway */
  encrypted_payload: z.string(),
  created_at: z.string().datetime(),
});
export type OverlayMessage = z.infer<typeof OverlayMessageSchema>;

// ─────────────────────────────────────────────────────────────────────────────
// Power Accumulation Score (§10)
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Witness / Log Node (§7.7, §7.8)
// ─────────────────────────────────────────────────────────────────────────────

export const WitnessAttestationSchema = z.object({
  schema: z.literal('lattice.witness.v0.1'),
  witness_id: z.string(),
  attested_batch_ids: z.array(z.string()),
  cross_root: z.string(),
  created_at: z.string().datetime(),
  signature: z.string(),
});
export type WitnessAttestation = z.infer<typeof WitnessAttestationSchema>;

export const EquivocationReportSchema = z.object({
  schema: z.literal('lattice.equivocation.v0.1'),
  detected_by: z.string(),
  batch_id: z.string(),
  conflicting_roots: z.array(z.string()),
  detected_at: z.string().datetime(),
});
export type EquivocationReport = z.infer<typeof EquivocationReportSchema>;
