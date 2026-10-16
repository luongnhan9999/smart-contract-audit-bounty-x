# Portal Submission Draft — SmartContractAuditBountyX

**Portal Track:** Builder  
**Contribution Type:** Intelligent Contracts  
**Network:** studionet (Chain ID: 61999)  
**Contract Address:** `0xEB7B71C95335117e7152507D1e44f89F56999225`  
**Evidence URL 1:** `https://github.com/luongnhan9999/smart-contract-audit-bounty-x`  
**Evidence URL 2:** `https://explorer-studio.genlayer.com/address/0xEB7B71C95335117e7152507D1e44f89F56999225`  

---

### Title
```
SmartContractAuditBountyX — Autonomous Vulnerability Fix & Proof-of-Patch Escrow Protocol
```

### Notes / Description (<1000 characters)
```
SmartContractAuditBountyX is an autonomous vulnerability fix and Proof-of-Patch escrow protocol on GenLayer replacing centralized bug bounty committees and trust asymmetry with deterministic on-chain patch verification.

Project funders lock native GEN in escrow bound to canonical GitHub repositories, target file paths, and vulnerability descriptions. When an auditor submits a patch commit SHA, GenLayer validators scrape the patched source code directly from the canonical raw.githubusercontent.com host via gl.nondet.web.render and arbitrate exploit mitigation using an autonomous LLM validator jury via gl.vm.run_nondet.

Settlement enforces 100% discrete consensus: PATCH_VERIFIED_SECURE (100% payout to auditor), PARTIAL_COVERAGE (50% payout to auditor, 50% refund to funder), and VULNERABILITY_PERSISTS (0% payout, allowing re-submission). Path traversal prevention and a bounded recovery cancellation path guarantee capital safety. 9/9 unit tests passed. Deployed on studionet: 0xEB7B71C95335117e7152507D1e44f89F56999225.
```
