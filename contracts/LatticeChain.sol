// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LatticeChain Trust Anchor
 * @dev Federated trust registry + transparency checkpoints + key lifecycle roots.
 *      On-chain stores hashes and lifecycle metadata only (never private keys).
 *
 *      Governance: contract `owner` controls global registry + checkpoints.
 *      Per-namespace: `namespaceAdmin` (domain owner) may change routing hashes
 *      (`serviceCertHash`, `metadataHash`) and the DNS-level access policy
 *      (`publicAccess`, `credentialMask`, `minAssuranceLevel`). Gateways MUST
 *      enforce policy before forwarding to backends (see docs).
 *
 *      Namespaces: ASCII lowercase `*.lattice` (single label). Reserved official
 *      slugs → only `owner` may register them initially.
 */
contract LatticeChain {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not governance owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        reservedOfficialLatticeSlugs[keccak256(bytes("governments"))] = true;
        reservedOfficialLatticeSlugs[keccak256(bytes("lattice"))] = true;
        reservedOfficialLatticeSlugs[keccak256(bytes("system"))] = true;
        reservedOfficialLatticeSlugs[keccak256(bytes("registry"))] = true;
    }

    // --- IssuerRegistry + CertType ---

    struct CertType {
        bytes32 certTypeId;
        string name;
        uint8 assuranceLevel;
        bool active;
    }
    mapping(bytes32 => CertType) public certTypes;

    struct Issuer {
        bytes32 issuerId;
        bytes32 issuerType;
        bytes32 publicKeyHash;
        bool active;
    }
    mapping(bytes32 => Issuer) public issuers;
    mapping(bytes32 => mapping(bytes32 => bool)) public canIssue;

    // --- NamespaceRegistry ---

    /**
     * @dev `serviceCertHash` / `metadataHash` are opaque commitments (e.g. gateway URI,
     *      cert binding, policy JSON hash). `namespaceAdmin` may update routing + policy.
     * @dev `credentialMask` bits (OR semantics at gateway): 1=government-class,
     *      2=enterprise-class, 4=model-provider-class. If `publicAccess`, mask ignored.
     */
    struct NamespaceRecord {
        bytes32 nameHash;
        bytes32 ownerIssuerId;
        bytes32 serviceCertHash;
        bytes32 metadataHash;
        bool active;
        address namespaceAdmin;
        bool publicAccess;
        uint8 credentialMask;
        uint8 minAssuranceLevel;
    }
    mapping(bytes32 => NamespaceRecord) public namespaces;

    /// @notice Public overlay identities for Lattice nodes (Entry / Relay / Gateway). Governance-only writes.
    /// @dev `overlayPubKey` is opaque X25519 SPKI DER (base64-encoded off-chain becomes raw bytes here).
    ///      `tlsFingerprintSha256` is optional pin (zeros = TLS chain validation only).
    struct LatticeNode {
        bytes overlayPubKey;
        bytes32 tlsFingerprintSha256;
        uint8 roleBitmask; // 1 = ENTRY | 2 = RELAY | 4 = GATEWAY (OR allowed)
        bool active;
    }
    mapping(bytes32 => LatticeNode) public latticeNodes;

    /** keccak256(ascii lowercase slug) where slug is the label before `.lattice`. */
    mapping(bytes32 => bool) public reservedOfficialLatticeSlugs;

    /// Bit flags for `credentialMask` (accepted client *classes* — OR at verify time).
    uint8 public constant CRED_GOVERNMENT = 1;
    uint8 public constant CRED_ENTERPRISE = 2;
    uint8 public constant CRED_MODEL = 4;

    // --- Merkle revocation checkpoints ---

    struct RevocationCheckpoint {
        bytes32 issuerId;
        bytes32 merkleRoot;
        uint64 validFrom;
        uint64 validTo;
    }
    mapping(bytes32 => RevocationCheckpoint[]) public revocationCheckpoints;

    // --- CheckpointRegistry ---

    struct Checkpoint {
        bytes32 batchId;
        bytes32 merkleRoot;
        uint64 fromTimestamp;
        uint64 toTimestamp;
        uint64 actionCount;
        address signer;
    }
    mapping(bytes32 => Checkpoint) public checkpoints;

    // --- KeyRegistry ---

    enum KeyStatus {
        ACTIVE,
        DEPRECATED,
        RETIRED,
        REVOKED_LOST,
        REVOKED_COMPROMISED,
        SUSPENDED
    }

    struct KeyRecord {
        bytes32 subjectId;
        bytes32 keyId;
        bytes32 publicKeyHash;
        bytes32 keyPurpose;
        uint64 validFrom;
        uint64 validUntil;
        KeyStatus status;
    }

    mapping(bytes32 => mapping(bytes32 => KeyRecord)) public keysBySubject;

    // --- RecoveryRegistry ---

    struct RecoveryPolicy {
        bytes32 subjectId;
        uint8 threshold;
        uint64 timelockSeconds;
    }

    mapping(bytes32 => RecoveryPolicy) public recoveryPolicies;
    mapping(bytes32 => bytes32[]) public recoveryKeyIds;

    // --- RevocationRegistry ---

    struct RevocationEvent {
        bytes32 targetKeyId;
        bytes32 reasonCode;
        uint64 effectiveAt;
        uint64 suspectedFrom;
        bytes32 evidenceHash;
    }

    mapping(bytes32 => RevocationEvent[]) public keyRevocationEvents;

    // --- GovernanceRegistry ---

    struct SubjectFreeze {
        bool active;
        bool blockNewCertIssuance;
        bool blockHighRiskActions;
        bool allowReadOnlyVerification;
    }

    mapping(bytes32 => SubjectFreeze) public subjectFreezes;

    // --- Events ---

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event CertTypeRegistered(bytes32 indexed certTypeId, string name);
    event IssuerRegistered(bytes32 indexed issuerId, bytes32 issuerType, bytes32 publicKeyHash);
    event IssuerPermissionSet(bytes32 indexed issuerId, bytes32 indexed certTypeId, bool allowed);
    event NamespaceRegistered(
        bytes32 indexed nameHash,
        bytes32 indexed ownerIssuerId,
        string fqdn,
        address namespaceAdmin,
        bool publicAccess,
        uint8 credentialMask,
        uint8 minAssuranceLevel
    );
    event NamespaceServiceUpdated(bytes32 indexed nameHash, bytes32 serviceCertHash, bytes32 metadataHash);
    event NamespacePolicyUpdated(bytes32 indexed nameHash, bool publicAccess, uint8 credentialMask, uint8 minAssuranceLevel);
    event ReservedSlugUpdated(bytes32 indexed slugHash, bool reserved);
    event RevocationAnchored(bytes32 indexed issuerId, bytes32 merkleRoot);
    event CheckpointAnchored(bytes32 indexed batchId, bytes32 merkleRoot, uint64 actionCount);
    event KeyUpserted(bytes32 indexed subjectId, bytes32 keyId, KeyStatus status);
    event RecoveryPolicySet(bytes32 indexed subjectId, uint8 threshold, uint64 timelockSeconds);
    event KeyRevocationEvent(bytes32 indexed subjectId, bytes32 targetKeyId, bytes32 reasonCode);
    event SubjectFreezeSet(bytes32 indexed subjectId, bool active);
    event LatticeNodeRegistered(bytes32 indexed nodeIdHash, string nodeLabel);

    uint8 public constant LATTICE_ROLE_ENTRY = 1;
    uint8 public constant LATTICE_ROLE_RELAY = 2;
    uint8 public constant LATTICE_ROLE_GATEWAY = 4;

    // --- Ownership ---

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero owner");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // --- Issuer / cert type ---

    function registerCertType(bytes32 _certTypeId, string memory _name, uint8 _assuranceLevel) external onlyOwner {
        certTypes[_certTypeId] = CertType(_certTypeId, _name, _assuranceLevel, true);
        emit CertTypeRegistered(_certTypeId, _name);
    }

    function registerIssuer(bytes32 _issuerId, bytes32 _issuerType, bytes32 _publicKeyHash) external onlyOwner {
        issuers[_issuerId] = Issuer(_issuerId, _issuerType, _publicKeyHash, true);
        emit IssuerRegistered(_issuerId, _issuerType, _publicKeyHash);
    }

    function setIssuerPermission(bytes32 _issuerId, bytes32 _certTypeId, bool _allowed) external onlyOwner {
        require(issuers[_issuerId].active, "Issuer inactive");
        require(certTypes[_certTypeId].active, "CertType inactive");
        canIssue[_issuerId][_certTypeId] = _allowed;
        emit IssuerPermissionSet(_issuerId, _certTypeId, _allowed);
    }

    function setReservedOfficialSlug(string calldata slug, bool reserved) external onlyOwner {
        bytes memory s = bytes(slug);
        require(s.length > 0 && s.length <= 64, "Bad slug length");
        for (uint i = 0; i < s.length; i++) {
            require(s[i] != bytes1("."), "Slug must not contain dots");
        }
        bytes32 h = keccak256(s);
        reservedOfficialLatticeSlugs[h] = reserved;
        emit ReservedSlugUpdated(h, reserved);
    }

    /**
     * @param _namespaceAdmin address(0) → defaults to `msg.sender`.
     * @param _publicAccess if true, gateway treats namespace as open (no client cert class gate).
     * @param _credentialMask OR of CRED_* bits when !publicAccess; 0 with !publicAccess = deny-all at gateway.
     * @param _minAssuranceLevel minimum CertType.assuranceLevel on presented client cert (0 = no minimum).
     */
    function registerNamespace(
        string calldata fqdn,
        bytes32 _ownerIssuerId,
        bytes32 _serviceCertHash,
        bytes32 _metadataHash,
        address _namespaceAdmin,
        bool _publicAccess,
        uint8 _credentialMask,
        uint8 _minAssuranceLevel
    ) external {
        require(issuers[_ownerIssuerId].active, "Issuer inactive");
        (bool ok, bytes32 nameHash, bytes32 slugHash) = _parseLatticeFqdn(fqdn);
        require(ok, "Invalid lattice FQDN");
        if (reservedOfficialLatticeSlugs[slugHash]) {
            require(msg.sender == owner, "Reserved official namespace");
        }
        require(namespaces[nameHash].ownerIssuerId == bytes32(0), "Namespace taken");

        address admin = _namespaceAdmin == address(0) ? msg.sender : _namespaceAdmin;

        namespaces[nameHash] = NamespaceRecord({
            nameHash: nameHash,
            ownerIssuerId: _ownerIssuerId,
            serviceCertHash: _serviceCertHash,
            metadataHash: _metadataHash,
            active: true,
            namespaceAdmin: admin,
            publicAccess: _publicAccess,
            credentialMask: _credentialMask,
            minAssuranceLevel: _minAssuranceLevel
        });
        emit NamespaceRegistered(nameHash, _ownerIssuerId, fqdn, admin, _publicAccess, _credentialMask, _minAssuranceLevel);
    }

    /// @notice Domain owner (`namespaceAdmin`) or contract owner may update routing / binding hashes.
    function updateNamespaceServiceBinding(
        string calldata fqdn,
        bytes32 newServiceCertHash,
        bytes32 newMetadataHash
    ) external {
        (bool ok, bytes32 nameHash, ) = _parseLatticeFqdn(fqdn);
        require(ok, "Invalid lattice FQDN");
        NamespaceRecord storage n = namespaces[nameHash];
        require(n.ownerIssuerId != bytes32(0), "Unknown namespace");
        require(msg.sender == n.namespaceAdmin || msg.sender == owner, "Not namespace admin");
        n.serviceCertHash = newServiceCertHash;
        n.metadataHash = newMetadataHash;
        emit NamespaceServiceUpdated(nameHash, newServiceCertHash, newMetadataHash);
    }

    /// @notice Domain owner or contract owner may change DNS-level access policy (gateway-enforced).
    function setNamespaceAccessPolicy(
        string calldata fqdn,
        bool publicAccess,
        uint8 credentialMask,
        uint8 minAssuranceLevel
    ) external {
        (bool ok, bytes32 nameHash, ) = _parseLatticeFqdn(fqdn);
        require(ok, "Invalid lattice FQDN");
        NamespaceRecord storage n = namespaces[nameHash];
        require(n.ownerIssuerId != bytes32(0), "Unknown namespace");
        require(msg.sender == n.namespaceAdmin || msg.sender == owner, "Not namespace admin");
        n.publicAccess = publicAccess;
        n.credentialMask = credentialMask;
        n.minAssuranceLevel = minAssuranceLevel;
        emit NamespacePolicyUpdated(nameHash, publicAccess, credentialMask, minAssuranceLevel);
    }

    function registerLatticeNode(
        string calldata nodeLabel,
        bytes calldata overlayPubKey,
        bytes32 tlsFingerprintSha256,
        uint8 roleBitmask
    ) external onlyOwner {
        require(bytes(nodeLabel).length != 0, "Empty nodeLabel");
        require(roleBitmask != 0, "No role flags");
        require(overlayPubKey.length > 0, "Missing overlay pubkey");
        bytes32 id = keccak256(bytes(nodeLabel));
        latticeNodes[id] = LatticeNode(overlayPubKey, tlsFingerprintSha256, roleBitmask, true);
        emit LatticeNodeRegistered(id, nodeLabel);
    }

    function setLatticeNodeActive(string calldata nodeLabel, bool active) external onlyOwner {
        bytes32 id = keccak256(bytes(nodeLabel));
        require(latticeNodes[id].overlayPubKey.length != 0, "Unknown lattice node");
        latticeNodes[id].active = active;
    }

    function anchorRevocation(bytes32 _issuerId, bytes32 _merkleRoot, uint64 _validFrom, uint64 _validTo) external onlyOwner {
        require(issuers[_issuerId].active, "Issuer inactive");
        revocationCheckpoints[_issuerId].push(RevocationCheckpoint(_issuerId, _merkleRoot, _validFrom, _validTo));
        emit RevocationAnchored(_issuerId, _merkleRoot);
    }

    function submitCheckpoint(
        bytes32 batchId,
        bytes32 merkleRoot,
        uint64 fromTimestamp,
        uint64 toTimestamp,
        uint64 actionCount
    ) external onlyOwner {
        require(checkpoints[batchId].merkleRoot == bytes32(0), "Checkpoint exists");
        checkpoints[batchId] = Checkpoint({
            batchId: batchId,
            merkleRoot: merkleRoot,
            fromTimestamp: fromTimestamp,
            toTimestamp: toTimestamp,
            actionCount: actionCount,
            signer: msg.sender
        });
        emit CheckpointAnchored(batchId, merkleRoot, actionCount);
    }

    function upsertKey(
        bytes32 subjectId,
        bytes32 keyId,
        bytes32 publicKeyHash,
        bytes32 keyPurpose,
        uint64 validFrom,
        uint64 validUntil,
        KeyStatus status
    ) external onlyOwner {
        keysBySubject[subjectId][keyId] = KeyRecord(subjectId, keyId, publicKeyHash, keyPurpose, validFrom, validUntil, status);
        emit KeyUpserted(subjectId, keyId, status);
    }

    function setRecoveryPolicy(
        bytes32 subjectId,
        uint8 threshold,
        uint64 timelockSeconds,
        bytes32[] calldata keyIds
    ) external onlyOwner {
        recoveryPolicies[subjectId] = RecoveryPolicy(subjectId, threshold, timelockSeconds);
        recoveryKeyIds[subjectId] = keyIds;
        emit RecoveryPolicySet(subjectId, threshold, timelockSeconds);
    }

    function appendKeyRevocation(
        bytes32 subjectId,
        bytes32 targetKeyId,
        bytes32 reasonCode,
        uint64 effectiveAt,
        uint64 suspectedFrom,
        bytes32 evidenceHash
    ) external onlyOwner {
        keyRevocationEvents[subjectId].push(
            RevocationEvent(targetKeyId, reasonCode, effectiveAt, suspectedFrom, evidenceHash)
        );
        emit KeyRevocationEvent(subjectId, targetKeyId, reasonCode);
    }

    function setSubjectFreeze(
        bytes32 subjectId,
        bool active,
        bool blockNewCertIssuance,
        bool blockHighRiskActions,
        bool allowReadOnlyVerification
    ) external onlyOwner {
        subjectFreezes[subjectId] = SubjectFreeze(active, blockNewCertIssuance, blockHighRiskActions, allowReadOnlyVerification);
        emit SubjectFreezeSet(subjectId, active);
    }

    function _parseLatticeFqdn(string memory fqdn)
        internal
        pure
        returns (bool ok, bytes32 nameHash, bytes32 slugHash)
    {
        bytes memory b = bytes(fqdn);
        if (b.length < 9) return (false, 0, 0);

        bytes memory suffix = ".lattice";
        for (uint i = 0; i < 8; i++) {
            if (b[b.length - 8 + i] != suffix[i]) return (false, 0, 0);
        }

        uint prefixLen = b.length - 8;
        if (prefixLen == 0) return (false, 0, 0);

        for (uint j = 0; j < prefixLen; j++) {
            uint8 c = uint8(b[j]);
            bool isLower = c >= 97 && c <= 122;
            bool isDigit = c >= 48 && c <= 57;
            bool isHyphen = c == 45;
            if (!isLower && !isDigit && !isHyphen) return (false, 0, 0);
        }

        bytes memory slug = new bytes(prefixLen);
        for (uint k = 0; k < prefixLen; k++) {
            slug[k] = b[k];
        }
        slugHash = keccak256(slug);
        nameHash = keccak256(b);
        return (true, nameHash, slugHash);
    }
}
