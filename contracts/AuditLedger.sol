// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuditLedger {
    address public owner;

    struct AuditRecord {
        string scanId;
        string reportHash;
        uint256 timestamp;
        address issuer;
        bool exists;
    }

    mapping(string => AuditRecord) public auditRegistry;
    string[] public scanHistory;

    // EVM Event for frontend indexing
    event AuditRecorded(string indexed scanId, string reportHash, uint256 timestamp, address indexed issuer);

    constructor() {
        owner = msg.sender; // The account that deploys this contract becomes the admin
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the system administrator can commit audits");
        _;
    }

    // Write hash to blockchain
    function recordAudit(string memory _scanId, string memory _reportHash) public onlyOwner {
        require(!auditRegistry[_scanId].exists, "Scan ID already exists");
        require(bytes(_reportHash).length == 64, "Invalid SHA-256 hash length");

        auditRegistry[_scanId] = AuditRecord({
            scanId: _scanId,
            reportHash: _reportHash,
            timestamp: block.timestamp,
            issuer: msg.sender,
            exists: true
        });

        scanHistory.push(_scanId);
        emit AuditRecorded(_scanId, _reportHash, block.timestamp, msg.sender);
    }

    // Verify hash from blockchain
    function verifyAudit(string memory _scanId) public view returns (string memory, uint256, address) {
        require(auditRegistry[_scanId].exists, "Scan ID not found");
        AuditRecord memory record = auditRegistry[_scanId];
        return (record.reportHash, record.timestamp, record.issuer);
    }
}