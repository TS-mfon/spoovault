// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../contracts/SpooVault.sol";

/**
 * @title SpooVaultFuzz
 * @dev Differential / invariant fuzzing harness for the SpooVault EVM contract.
 *
 *      This contract is *not* deployed in production. It is consumed by:
 *        - Echidna  (https://github.com/crytic/echidna)  -> checks `echidna_*` properties
 *        - Medusa   (https://github.com/crytic/medusa)   -> checks `invariant_*` properties
 *
 *      Design notes:
 *        * The deployer (msg.sender during fuzzing) is registered as the sole
 *          external guardian of a bootstrap vault and is minted a vault access
 *          NFT, so every fuzzable action can be exercised by the fuzzer as a
 *          legitimate actor (guardian + token holder).
 *        * A fixed `ATTACKER` address is never granted access, so the
 *          "unauthorized user cannot access" invariant stays meaningful.
 *        * `mintedCount` / `burnedCount` shadow the contract's internal
 *          `_activeTokenSupply` so we can assert the NFT supply accounting
 *          invariant end-to-end.
 */
contract SpooVaultFuzz is SpooVault {
    address public constant ATTACKER = address(0x00000000000000000000000000000000DEAD0001);

    uint256 public vaultId;
    uint256[] private documentIds;
    uint256[] private requestIds;
    uint256[] private mintedTokens;
    mapping(uint256 => bool) private burnedTokens;
    // Model tracking: how many approvals the fuzzer actor has supplied per request.
    mapping(uint256 => uint256) private approvalsMade;
    mapping(uint256 => bool) private hasApprovedReq;

    uint256 public mintedCount;
    uint256 public burnedCount;

    constructor() {
        address[] memory guardians = new address[](1);
        guardians[0] = msg.sender; // fuzzer actor becomes the guardian
        vaultId = this.createVault("Fuzz Vault", "fuzz", guardians, 1);

        // Mint an access NFT to the fuzzer actor so it can request access.
        uint256 tid = this.mintAccessToken(vaultId, msg.sender, "fuzz-token");
        mintedCount += 1;
        mintedTokens.push(tid);

        // Seed one document so request/approve flows have something to act on.
        uint256 did = this.addDocument(vaultId, "fuzz-meta", "QmFuzzSeed", AccessLevel.READ);
        documentIds.push(did);
    }

    // ------------------------------------------------------------------
    // Fuzzable actions (Echidna/Medusa call these with random arguments)
    // ------------------------------------------------------------------

    /// @dev Add a new document (actor is a guardian).
    function fuzz_addDocument() external {
        uint256 did = this.addDocument(vaultId, "fuzz-meta", "QmFuzzHash", AccessLevel.READ);
        documentIds.push(did);
    }

    /// @dev Request access to the most recently added document (actor owns a token).
    function fuzz_request() external {
        if (documentIds.length == 0) return;
        uint256 did = documentIds[documentIds.length - 1];
        uint256 rid = this.requestAccess(did);
        requestIds.push(rid);
    }

    /// @dev Approve a pending access request by index (actor is a guardian).
    function fuzz_approve(uint256 idx) external {
        if (idx < requestIds.length) {
            uint256 rid = requestIds[idx];
            if (!hasApprovedReq[rid]) {
                _approveAccess(rid, "");
                hasApprovedReq[rid] = true;
                approvalsMade[rid] = 1;
            }
        }
    }

    /// @dev Mint an access NFT to the actor (guardian) and track supply.
    function fuzz_mint() external {
        uint256 tid = this.mintAccessToken(vaultId, msg.sender, "fuzz-token");
        mintedCount += 1;
        mintedTokens.push(tid);
    }

    /// @dev Burn a previously fuzzed-minted token and track supply.
    function fuzz_burn(uint256 idx) external {
        if (idx >= mintedTokens.length) return;
        uint256 tid = mintedTokens[idx];
        if (burnedTokens[tid]) return;
        burnedTokens[tid] = true;
        burnedCount += 1;
        this.burnAccessToken(tid);
    }

    // ------------------------------------------------------------------
    // Invariant helpers
    // ------------------------------------------------------------------

    function _checkApprovalThreshold() private view returns (bool) {
        for (uint256 i = 0; i < requestIds.length; i++) {
            uint256 rid = requestIds[i];

            uint256 aDoc;
            RequestStatus aStatus;
            // AccessRequest getter tuple (requestId, documentId, requester, status, expiresAt, createdAt)
            (, aDoc, , aStatus, , ) = this.accessRequests(rid);

            uint256 dVid;
            // Document getter tuple (id, vaultId, encryptedMetadata, ipfsHash, uploadedBy, uploadedAt, requiredAccess)
            (, dVid, , , , , ) = this.documents(aDoc);

            uint256 vThr;
            // Vault getter tuple (id, creator, name, description, approvalThreshold, isActive, createdAt)
            // NOTE: dynamic `guardians` array is omitted from the public getter.
            (, , , , vThr, , ) = this.vaults(dVid);

            uint256 made = approvalsMade[rid];
            bool approved = (uint256(aStatus) == 1 /* APPROVED */);

            // (a) The contract must never mark a request APPROVED with fewer
            //     approvals than the configured threshold.
            if (approved && made < vThr) {
                return false;
            }
            // (b) Once the threshold of approvals is reached, the request must be
            //     APPROVED (the contract must not silently under-approve).
            if (made >= vThr && !approved) {
                return false;
            }
            // (c) The actor can supply at most the number of guardians (here 2),
            //     so the approval count can never exceed the guardian set.
            if (made > 2) {
                return false;
            }
        }
        return true;
    }

    function _checkUnauthorized() private view returns (bool) {
        for (uint256 i = 0; i < documentIds.length; i++) {
            if (this.hasActiveAccess(documentIds[i], ATTACKER)) {
                return false;
            }
        }
        if (this.hasVaultToken(ATTACKER, vaultId)) {
            return false;
        }
        return true;
    }

    function _checkSupply() private view returns (bool) {
        return this.totalSupply() == (mintedCount - burnedCount);
    }

    // ------------------------------------------------------------------
    // Property functions
    // ------------------------------------------------------------------

    /// @custom:echidna The number of approvals on any request never exceeds the guardian set,
    /// and once approved it meets the threshold.
    function echidna_approval_threshold_never_exceeded() public view returns (bool) {
        return _checkApprovalThreshold();
    }

    /// @custom:echidna The designated attacker never obtains access.
    function echidna_unauthorized_user_cannot_access() public view returns (bool) {
        return _checkUnauthorized();
    }

    /// @custom:echidna Mint/burn NFT supply accounting stays consistent.
    function echidna_vault_balance_sum_equals_total_supply() public view returns (bool) {
        return _checkSupply();
    }

    // Medusa uses the `invariant_*` convention (mirrors the echidna properties).
    function invariant_approval_threshold_never_exceeded() public view returns (bool) {
        return _checkApprovalThreshold();
    }

    function invariant_unauthorized_user_cannot_access() public view returns (bool) {
        return _checkUnauthorized();
    }

    function invariant_vault_balance_sum_equals_total_supply() public view returns (bool) {
        return _checkSupply();
    }
}
