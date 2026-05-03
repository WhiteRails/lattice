# White Protocol MVP

This repository contains a Minimum Viable Product (MVP) implementation of the **White Protocol** and **WhiteNet**.

The White Protocol provides an open trust, traceability, and capability governance layer for autonomous AI agents. It enables secure delegation of authority from humans/organizations to agents and provides a verifiable audit trail for agent actions.

## Key Components

- **Identity (`src/identity.ts`)**: Implements Ed25519-based identity management, including key pair generation, certificate creation (AgentCert), and cryptographic signing/verification.
- **Addressing (`src/addressing.ts`)**: Implements WhiteNet's self-authenticating addresses. Addresses are derived from the SHA-256 hash of a public key, base32 encoded, and suffixed with `.white`.
- **Envelope (`src/envelope.ts`)**: Defines the **Signed Agent Action Envelope (SAAE)**, the core data structure for recording and verifying agent actions.
- **Gateway (`src/gateway.ts`)**: The `WhiteGateway` mediates tool calls by agents, ensuring they have the necessary capabilities, checking for revocations, and enforcing security policies.
- **PAS (`src/pas.ts`)**: The **Power Accumulation Tracker** monitors agent activities across various factors (e.g., compute acquired, money accessible) to calculate a risk score.
- **Registry (`src/registry.ts`)**: The `WhiteRegistry` maps WhiteNet addresses to registry records, including public keys and certificate chains.
- **Revocation (`src/revocation.ts`)**: The `RevocationNetwork` allows for publishing and verifying revocation records for certificates and other protocol objects.

## Getting Started

### Prerequisites

- Node.js (v20 or higher recommended)
- npm

### Installation

```bash
npm install
```

### Development Scripts

- **Run tests**: `npm test`
- **Build project**: `npm run build`

## Architecture Overview

1. **Identity & Addressing**: Agents and services are identified by WhiteNet addresses derived from their public keys.
2. **Delegation**: Humans or organizations delegate specific capabilities to agents via `DelegationGrant` and `IntentAnchor` objects.
3. **Mediation**: When an agent wants to perform an action (e.g., call a tool), it submits the request to a `WhiteGateway`.
4. **Validation**: The gateway validates the agent's identity, its delegated authority, and checks for any revocations. It also updates the agent's **Power Accumulation Score (PAS)**.
5. **Verification**: If validated, a **SAAE** is produced, creating a verifiable record of the action and the authority under which it was performed.

## License

MIT
