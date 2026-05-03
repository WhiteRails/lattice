// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LatticeChain Trust Anchor
 * @dev Federated trust registry + transparency checkpoints + key lifecycle roots.
 *      On-chain stores hashes and lifecycle metadata only (never private keys).
 *
 *      Logical modules (single deployable unit for the MVP toolchain):
 *      — IssuerRegistry + CertType registry
 *      — NamespaceRegistry
 *      — KeyRegistry + RecoveryRegistry
 *      — RevocationRegistry (per-key events) + legacy Merkle revocation checkpoints
 *      — CheckpointRegistry (signed log roots)
 *      — GovernanceRegistry (subject freeze)
 */
contract LatticeChain {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not governance owner");
        _;
    }

    constructor() {
        owner = msg.sender;
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

    struct NamespaceRecord {
        bytes32 nameHash;
        bytes32 ownerIssuerId;
        bytes32 serviceCertHash;
        bytes32 metadataHash;
        bool active;
    }
    mapping(bytes32 => NamespaceRecord) public namespaces;

    // --- Merkle revocation checkpoints (bulk transparency) ---

    struct RevocationCheckpoint {
        bytes32 issuerId;
        bytes32 merkleRoot;
        uint64 validFrom;
        uint64 validTo;
    }
    mapping(bytes32 => RevocationCheckpoint[]) public revocationCheckpoints;

    // --- CheckpointRegistry (signed batch / log roots) — used by node/chain.ts ---

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

    // --- RevocationRegistry (key lifecycle evidence) ---

    struct RevocationEvent {
        bytes32 targetKeyId;
        bytes32 reasonCode;
        uint64 effectiveAt;
        uint64 suspectedFrom;
        bytes32 evidenceHash;
    }

    mapping(bytes32 => RevocationEvent[]) public keyRevocationEvents;

    // --- GovernanceRegistry (emergency freeze) ---

    struct SubjectFreeze {
        bool active;
        bool blockNewCertIssuance;
        bool blockHighRiskActions;
        bool allowReadOnlyVerification;
    }

    mapping(bytes32 => SubjectFreeze) public subjectFreezes;

    // --- Events ---

    event CertTypeRegistered(bytes32 indexed certTypeId, string name);
    event IssuerRegistered(bytes32 indexed issuerId, bytes32 issuerType, bytes32 publicKeyHash);
    event IssuerPermissionSet(bytes32 indexed issuerId, bytes32 indexed certTypeId, bool allowed);
    event NamespaceRegistered(bytes32 indexed nameHash, bytes32 indexed ownerIssuerId);
    event RevocationAnchored(bytes32 indexed issuerId, bytes32 merkleRoot);
    event CheckpointAnchored(bytes32 indexed batchId, bytes32 merkleRoot, uint64 actionCount);
    event KeyUpserted(bytes32 indexed subjectId, bytes32 indexed keyId, KeyStatus status);
    event RecoveryPolicySet(bytes32 indexed subjectId, uint8 threshold, uint64 timelockSeconds);
    event KeyRevocationEvent(bytes32 indexed subjectId, bytes32 indexed targetKeyId, bytes32 reasonCode);
    event SubjectFreezeSet(bytes32 indexed subjectId, bool active);

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

    function registerNamespace(
        bytes32 _nameHash,
        bytes32 _ownerIssuerId,
        bytes32 _serviceCertHash,
        bytes32 _metadataHash
    ) external {
        require(issuers[_ownerIssuerId].active, "Issuer inactive");
        namespaces[_nameHash] = NamespaceRecord(_nameHash, _ownerIssuerId, _serviceCertHash, _metadataHash, true);
        emit NamespaceRegistered(_nameHash, _ownerIssuerId);
    }

    function anchorRevocation(bytes32 _issuerId, bytes32 _merkleRoot, uint64 _validFrom, uint64 _validTo) external {
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
    ) external {
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

    // --- KeyRegistry ---

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

    // --- RecoveryRegistry ---

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

    // --- RevocationRegistry ---

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

    // --- GovernanceRegistry ---

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
}
