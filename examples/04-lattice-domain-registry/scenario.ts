/**
 * Example 04 — LatticeChain domain (namespace) management
 *
 * Demonstrates every namespace-related option on LatticeChain and the matching
 * helpers in `node/chain.ts`, plus gateway-side policy checks from `core/namespace-access.ts`.
 *
 * Run: npm run example:domains
 *
 * Env:
 *   LATTICE_RPC_URL              (default http://127.0.0.1:8545)
 *   LATTICE_CHAIN_PRIVATE_KEY    (required, 0x…)
 *   LATTICE_CHAIN_ADDRESS        (optional; if unset, deploys a new contract)
 *   LATTICE_NAMESPACE_FQDN       (optional; default generated to avoid "Namespace taken")
 *   LATTICE_NAMESPACE_ADMIN      (optional; 0x… extra domain admin, else registrar is admin)
 */

import { ethers } from 'ethers';
import {
  deployLatticeChain,
  chainRegisterCertType,
  chainRegisterIssuer,
  chainSetIssuerPermission,
  chainRegisterNamespace,
  chainUpdateNamespaceServiceBinding,
  chainSetNamespaceAccessPolicy,
  chainGetNamespace,
  chainGetReservedOfficialSlug,
} from '../../node/chain';
import {
  CRED_ENTERPRISE,
  CRED_GOVERNMENT,
  CRED_MODEL,
  clientMeetsNamespacePolicy,
  credentialMaskFromNames,
} from '../../core/namespace-access';

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const grn = (s: string) => `\x1b[32m${s}\x1b[0m`;

function logStep(n: number, title: string) {
  console.log(`\n${bold(`Step ${n}: ${title}`)}`);
}

function mustEnv(name: string): string {
  const v = process.env[name]?.trim();
  if (!v) {
    console.error(
      [
        `Missing ${name}.`,
        '',
        'Example:',
        '  export LATTICE_CHAIN_PRIVATE_KEY=0x…',
        '  export LATTICE_RPC_URL=http://127.0.0.1:8545   # optional',
        '  export LATTICE_CHAIN_ADDRESS=0x…             # optional (else deploy)',
        '  npm run example:domains',
      ].join('\n'),
    );
    process.exit(1);
  }
  return v;
}

/** Deterministic demo bytes32 commitments (not real cert hashes). */
function demoBinding(label: string, version: string): string {
  return ethers.id(`example04:${label}:${version}`);
}

function defaultFqdn(): string {
  const custom = process.env.LATTICE_NAMESPACE_FQDN?.trim();
  if (custom) return custom;
  const t = Math.floor(Date.now() / 1000);
  return `ex04-${t}.lattice`;
}

async function main() {
  const rpcUrl = process.env.LATTICE_RPC_URL?.trim() || 'http://127.0.0.1:8545';
  const privateKey = mustEnv('LATTICE_CHAIN_PRIVATE_KEY');
  const wallet = new ethers.Wallet(privateKey);
  const adminEnv = process.env.LATTICE_NAMESPACE_ADMIN?.trim();

  console.log(bold('\n=== Example 04: LatticeChain domain registry ==='));
  console.log(dim(`RPC: ${rpcUrl}`));
  console.log(dim(`Signer: ${wallet.address}`));

  let contractAddress = process.env.LATTICE_CHAIN_ADDRESS?.trim();
  if (!contractAddress) {
    logStep(0, 'Deploy LatticeChain (no LATTICE_CHAIN_ADDRESS)');
    contractAddress = await deployLatticeChain(rpcUrl, privateKey);
    console.log(`${grn('✓')} Deployed at ${contractAddress}`);
  } else {
    console.log(dim(`Contract: ${contractAddress}`));
  }

  const fqdn = defaultFqdn();
  const issuerLabel = 'ex04-domain-owner-issuer';
  const issuerTypeLabel = 'ex04-issuer-type';
  const demoPkHash = ethers.id('ex04:issuer:demo-public-key-material');

  // ── Contract owner: cert types (all options: name + assuranceLevel) ───────
  logStep(1, 'Owner registers cert types (registerCertType)');
  await chainRegisterCertType(rpcUrl, privateKey, contractAddress, 'gov-class', 3);
  console.log(`${grn('✓')} cert type gov-class assuranceLevel=3`);
  await chainRegisterCertType(rpcUrl, privateKey, contractAddress, 'enterprise-class', 2);
  console.log(`${grn('✓')} cert type enterprise-class assuranceLevel=2`);
  await chainRegisterCertType(rpcUrl, privateKey, contractAddress, 'model-class', 1);
  console.log(`${grn('✓')} cert type model-class assuranceLevel=1`);

  // ── Owner: issuer + permissions (issuer must be active for namespace ownerIssuerId) ──
  logStep(2, 'Owner registers issuer + setIssuerPermission');
  await chainRegisterIssuer(rpcUrl, privateKey, contractAddress, issuerLabel, issuerTypeLabel, demoPkHash);
  console.log(`${grn('✓')} issuer "${issuerLabel}"`);
  await chainSetIssuerPermission(rpcUrl, privateKey, contractAddress, issuerLabel, 'gov-class', true);
  await chainSetIssuerPermission(rpcUrl, privateKey, contractAddress, issuerLabel, 'enterprise-class', true);
  await chainSetIssuerPermission(rpcUrl, privateKey, contractAddress, issuerLabel, 'model-class', true);
  console.log(`${grn('✓')} issuer may issue gov-class, enterprise-class, model-class`);

  // ── Read-only: built-in reserved official slugs (constructor / setReservedOfficialSlug) ──
  logStep(3, 'Read reserved slug flags (reservedOfficialLatticeSlugs)');
  for (const slug of ['governments', 'lattice', 'system', 'registry']) {
    const reserved = await chainGetReservedOfficialSlug(rpcUrl, contractAddress, slug);
    console.log(dim(`  slug "${slug}" reserved=${reserved}`));
  }

  const serviceV1 = demoBinding('service', 'v1');
  const metaV1 = demoBinding('metadata', 'v1');
  const namespaceAdmin =
    adminEnv && adminEnv.length > 0 ? ethers.getAddress(adminEnv) : undefined;

  // ── registerNamespace: every argument variant is exercised across steps ─────
  logStep(4, 'registerNamespace — restricted + credential mask + minAssurance');
  const maskGovOrEnterprise = credentialMaskFromNames(['gov', 'enterprise']);
  console.log(
    dim(
      `  Solidity CRED_GOVERNMENT=${CRED_GOVERNMENT} CRED_ENTERPRISE=${CRED_ENTERPRISE} CRED_MODEL=${CRED_MODEL} → mask OR = ${maskGovOrEnterprise}`,
    ),
  );
  await chainRegisterNamespace(
    rpcUrl,
    privateKey,
    contractAddress,
    fqdn,
    issuerLabel,
    serviceV1,
    metaV1,
    namespaceAdmin,
    false,
    maskGovOrEnterprise,
    2,
  );
  console.log(`${grn('✓')} Registered ${fqdn} (publicAccess=false, minAssuranceLevel=2)`);

  let row = await chainGetNamespace(rpcUrl, contractAddress, fqdn);
  console.log(dim(`  chainGetNamespace: ${JSON.stringify(row, null, 2)}`));

  // ── updateNamespaceServiceBinding (namespaceAdmin or owner) ──────────────
  logStep(5, 'updateNamespaceServiceBinding — new service + metadata hashes');
  const serviceV2 = demoBinding('service', 'v2');
  const metaV2 = demoBinding('metadata', 'v2');
  const txBind = await chainUpdateNamespaceServiceBinding(
    rpcUrl,
    privateKey,
    contractAddress,
    fqdn,
    serviceV2,
    metaV2,
  );
  console.log(`${grn('✓')} Binding updated tx=${txBind}`);
  row = await chainGetNamespace(rpcUrl, contractAddress, fqdn);
  console.log(dim(`  serviceCertHash: ${row.serviceCertHash}`));
  console.log(dim(`  metadataHash:    ${row.metadataHash}`));

  // Partial update: only metadata (TS merges the other field from chain state)
  logStep(6, 'updateNamespaceServiceBinding — metadata only (single-arg merge)');
  const metaV3 = demoBinding('metadata', 'v3');
  await chainUpdateNamespaceServiceBinding(rpcUrl, privateKey, contractAddress, fqdn, undefined, metaV3);
  row = await chainGetNamespace(rpcUrl, contractAddress, fqdn);
  console.log(`${grn('✓')} service unchanged, metadata → v3`);

  // ── setNamespaceAccessPolicy — flip to public, then to model-only + assurance ──
  logStep(7, 'setNamespaceAccessPolicy — publicAccess true');
  await chainSetNamespaceAccessPolicy(rpcUrl, privateKey, contractAddress, fqdn, true, 0, 0);
  row = await chainGetNamespace(rpcUrl, contractAddress, fqdn);
  console.log(`${grn('✓')} publicAccess=${row.publicAccess} credentialMask=${row.credentialMask}`);

  logStep(8, 'setNamespaceAccessPolicy — government OR model, minAssurance 3');
  const maskGovOrModel = CRED_GOVERNMENT | CRED_MODEL;
  await chainSetNamespaceAccessPolicy(rpcUrl, privateKey, contractAddress, fqdn, false, maskGovOrModel, 3);
  row = await chainGetNamespace(rpcUrl, contractAddress, fqdn);
  console.log(`${grn('✓')} policy row: ${JSON.stringify(row, null, 2)}`);

  // ── Gateway-side helper (off-chain, same semantics as docs) ───────────────
  logStep(9, 'clientMeetsNamespacePolicy (gateway simulation)');
  const policy = {
    publicAccess: row.publicAccess,
    credentialMask: row.credentialMask,
    minAssuranceLevel: row.minAssuranceLevel,
  };
  const cases = [
    { label: 'enterprise client, assurance 5', mask: CRED_ENTERPRISE, level: 5 },
    { label: 'government client, assurance 3', mask: CRED_GOVERNMENT, level: 3 },
    { label: 'government client, assurance 2 (below min 3)', mask: CRED_GOVERNMENT, level: 2 },
  ];
  for (const c of cases) {
    const r = clientMeetsNamespacePolicy(policy, c.mask, c.level);
    if (r.ok) {
      console.log(dim(`  ${c.label} → ALLOW`));
    } else {
      console.log(dim(`  ${c.label} → DENY (${r.reason})`));
    }
  }

  console.log(bold('\n=== Done ==='));
  console.log(dim(`Contract: ${contractAddress}`));
  console.log(dim(`FQDN:     ${fqdn}`));
  console.log(dim('Re-run with LATTICE_CHAIN_ADDRESS set to reuse the same deployment.'));
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
