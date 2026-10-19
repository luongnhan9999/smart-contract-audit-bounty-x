# Portal Submission Draft — SmartContractAuditBountyX

**Portal Track:** Builder  
**Contribution Type:** Intelligent Contracts  
**Network:** studionet (Chain ID: 61999)  
**Contract Address:** `0xdf7Dc08993611E2A28C0DDA82a2a7F6A6b82a878`  
**Evidence URL 1:** `https://github.com/luongnhan9999/smart-contract-audit-bounty-x`  
**Evidence URL 2:** `https://explorer-studio.genlayer.com/address/0xdf7Dc08993611E2A28C0DDA82a2a7F6A6b82a878`  

---

### Title
```
SmartContractAuditBountyX — Autonomous Vulnerability Fix & Proof-of-Patch Escrow Protocol
```

### Notes / Description (<1000 characters)
```
SmartContractAuditBountyX is an autonomous vulnerability fix and Proof-of-Patch escrow protocol on GenLayer replacing centralized bug bounty committees and trust asymmetry with deterministic on-chain patch verification.

Project funders lock native GEN in escrow bound to canonical GitHub repositories, target file paths, and vulnerability descriptions. When an auditor submits a patch commit SHA, GenLayer validators scrape the patched source code directly from canonical raw.githubusercontent.com via gl.nondet.web.render and arbitrate exploit mitigation and regressions using a Bounded Full-File & Chunked strategy via gl.vm.run_nondet (zero silent code omission).

Settlement enforces 100% discrete consensus: PATCH_VERIFIED_SECURE (100% payout to auditor), PARTIAL_COVERAGE (50% payout to auditor, 50% refund to funder), and VULNERABILITY_PERSISTS (0% payout, allowing re-submission). Path traversal prevention and a bounded recovery cancellation path guarantee capital safety. 12/12 unit tests passed. Deployed on studionet: 0xdf7Dc08993611E2A28C0DDA82a2a7F6A6b82a878.
```

---

### Response to Steward Request (Phản hồi cho Giám khảo Joaquin khi ấn Resubmit)
```text
Updated the adjudication engine to eliminate fixed prefix truncation (formerly [:4000]) in favor of a robust Bounded Full-File & Chunked Adjudication strategy:
1. Files <= 24,000 characters (~600-800 lines) are evaluated 100% untruncated with zero material code omission.
2. Files between 24,000 and 48,000 characters undergo sliding-window chunked evaluation (20k chunk size with 2k overlap) ensuring function boundaries and regressions across the entire file are evaluated.
3. Target files > 48,000 characters fail closed (VULNERABILITY_PERSISTS) with explicit messaging, strictly prohibiting silent omission.
4. Added 3 new unit tests (12/12 passing) verifying full-file evaluations past 4,000 chars, regression detection at file bottoms, and bounded upper limits.
5. Redeployed and verified on studionet: 0xdf7Dc08993611E2A28C0DDA82a2a7F6A6b82a878.
```
