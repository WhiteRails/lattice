// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LatticeChain
 * @dev Minimal public trust anchor for the Lattice overlay network.
 * It stores Merkle roots of off-chain action batches, ensuring that
 * agents' actions remain private and scalable while retaining public
 * auditable provenance.
 */
contract LatticeChain {
    struct Checkpoint {
        bytes32 merkleRoot;
        uint64 fromTimestamp;
        uint64 toTimestamp;
        uint64 actionCount;
        address signer;
    }

    // Mapping from a unique batch ID to its checkpoint metadata
    mapping(bytes32 => Checkpoint) public checkpoints;
    
    event CheckpointSubmitted(bytes32 indexed batchId, bytes32 merkleRoot, uint64 actionCount, address indexed signer);

    /**
     * @dev Submits a new batch checkpoint to the trust anchor.
     * @param batchId The unique ID of the batch (e.g. hash of the batch metadata)
     * @param merkleRoot The Merkle root of all action envelope hashes in the batch
     * @param fromTimestamp The earliest timestamp in the batch
     * @param toTimestamp The latest timestamp in the batch
     * @param actionCount The number of actions in the batch
     */
    function submitCheckpoint(
        bytes32 batchId,
        bytes32 merkleRoot,
        uint64 fromTimestamp,
        uint64 toTimestamp,
        uint64 actionCount
    ) external {
        require(checkpoints[batchId].merkleRoot == bytes32(0), "Batch already exists");
        require(merkleRoot != bytes32(0), "Invalid Merkle root");
        
        checkpoints[batchId] = Checkpoint(
            merkleRoot,
            fromTimestamp,
            toTimestamp,
            actionCount,
            msg.sender
        );
        
        emit CheckpointSubmitted(batchId, merkleRoot, actionCount, msg.sender);
    }
}
