import pytest
import json
from datetime import datetime, timezone, timedelta
from gltest import *
from conftest import sim_installMocks


@pytest.fixture
def contract(direct_deploy):
    return direct_deploy("contracts/smart_contract_audit_bounty_x.py")


def test_initial_state(contract, direct_vm, direct_alice, direct_bob):
    # Initial state checks
    assert contract.get_bounty_count() == 0
    owner_str = contract.get_owner().lower()
    expected_sender = direct_vm.sender.hex().lower() if isinstance(direct_vm.sender, bytes) else str(direct_vm.sender).lower()
    if not expected_sender.startswith("0x"):
        expected_sender = "0x" + expected_sender
    assert owner_str == expected_sender
    assert contract.get_current_time() >= 0


def test_create_bounty_success(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice  # Project funder
    direct_vm.value = 10000          # 10,000 GEN locked in escrow

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/defi-protocol/lending-core",
        vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
        target_file_path="contracts/LendingVault.sol",
        duration_sec=86400 * 7
    )

    assert bid == "1"
    assert contract.get_bounty_count() == 1

    b = json.loads(contract.get_bounty("1"))
    assert b["bounty_id"] == "1"
    assert b["project_funder"] == direct_alice.as_hex.lower()
    assert b["auditor"] == direct_bob.as_hex.lower()
    assert b["repo_url"] == "https://github.com/defi-protocol/lending-core"
    assert b["target_file_path"] == "contracts/LendingVault.sol"
    assert b["vulnerability_details"] == "Critical reentrancy in withdraw() allows draining collateral"
    assert b["bounty_reward"] == "10000"
    assert b["auditor_payout"] == "0"
    assert b["funder_refund"] == "0"
    assert b["status"] == "CREATED"
    assert b["verdict"] == "PENDING"
    assert b["patch_commit_sha"] == ""


def test_create_bounty_validations(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice

    # 1. Zero deposit
    direct_vm.value = 0
    with pytest.raises(Exception, match="Bounty reward must be greater than 0 GEN"):
        contract.create_bounty(
            auditor=direct_bob,
            repo_url="https://github.com/defi-protocol/lending-core",
            vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
            target_file_path="contracts/LendingVault.sol",
            duration_sec=86400 * 7
        )

    # 2. Funder and auditor cannot be the same address
    direct_vm.value = 5000
    with pytest.raises(Exception, match="Funder and auditor cannot be the same address"):
        contract.create_bounty(
            auditor=direct_alice,
            repo_url="https://github.com/defi-protocol/lending-core",
            vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
            target_file_path="contracts/LendingVault.sol",
            duration_sec=86400 * 7
        )

    # 3. Short vulnerability details (< 15 chars)
    with pytest.raises(Exception, match="vulnerability_details must be comprehensive"):
        contract.create_bounty(
            auditor=direct_bob,
            repo_url="https://github.com/defi-protocol/lending-core",
            vulnerability_details="bug here",
            target_file_path="contracts/LendingVault.sol",
            duration_sec=86400 * 7
        )

    # 4. Empty target file path
    with pytest.raises(Exception, match="target_file_path is required"):
        contract.create_bounty(
            auditor=direct_bob,
            repo_url="https://github.com/defi-protocol/lending-core",
            vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
            target_file_path="  ",
            duration_sec=86400 * 7
        )

    # 5. Non-github host
    with pytest.raises(Exception, match="Host must be authoritative github.com"):
        contract.create_bounty(
            auditor=direct_bob,
            repo_url="https://gitlab.com/defi-protocol/lending-core",
            vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
            target_file_path="contracts/LendingVault.sol",
            duration_sec=86400 * 7
        )

    # 6. Invalid repo URL format (missing repo or owner)
    with pytest.raises(Exception, match="Invalid repository URL format"):
        contract.create_bounty(
            auditor=direct_bob,
            repo_url="https://github.com/defi-protocol",
            vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
            target_file_path="contracts/LendingVault.sol",
            duration_sec=86400 * 7
        )

    # 7. Path traversal injection
    with pytest.raises(Exception, match="Invalid relative path components"):
        contract.create_bounty(
            auditor=direct_bob,
            repo_url="https://github.com/defi-protocol/lending-core",
            vulnerability_details="Critical reentrancy in withdraw() allows draining collateral",
            target_file_path="contracts/../../etc/passwd",
            duration_sec=86400 * 7
        )


def test_submit_patch_flow(contract, direct_vm, direct_alice, direct_bob, direct_charlie):
    direct_vm.sender = direct_alice
    direct_vm.value = 5000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/defi-protocol/lending-core",
        vulnerability_details="Integer overflow in reward distributor contract logic",
        target_file_path="contracts/RewardDistributor.sol",
        duration_sec=86400 * 7
    )

    # 1. Non-existent bounty
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="Bounty not found"):
        contract.submit_patch("999", "a1b2c3d4e5f6")

    # 2. Unauthorized sender (not designated auditor)
    direct_vm.sender = direct_charlie
    with pytest.raises(Exception, match="Only designated auditor can submit patch"):
        contract.submit_patch(bid, "a1b2c3d4e5f6")

    # 3. Invalid commit SHA length (< 7)
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="Invalid commit SHA format"):
        contract.submit_patch(bid, "abc")

    # 4. Valid patch submission
    contract.submit_patch(bid, "7f8e9a0b1c2d3e4f")

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "SUBMITTED"
    assert b["patch_commit_sha"] == "7f8e9a0b1c2d3e4f"
    assert "7f8e9a0b1c2d3e4f" in b["reason"]


def test_adjudicate_patch_verified_secure_100_percent_payout(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    direct_vm.value = 12000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/smart-audit/vault",
        vulnerability_details="Reentrancy vulnerability in withdraw function leading to collateral loss",
        target_file_path="contracts/Vault.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    patch_sha = "c3d4e5f6a1b20001"
    contract.submit_patch(bid, patch_sha)

    # Setup web & LLM mocks
    patched_source = """
    contract Vault {
        bool private locked;
        modifier nonReentrant() {
            require(!locked, "REENTRANT");
            locked = true;
            _;
            locked = false;
        }
        function withdraw(uint256 amount) external nonReentrant {
            balances[msg.sender] -= amount;
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
        }
    }
    """
    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": patched_source}
        },
        "llm_mocks": {
            ".*": json.dumps({
                "verdict": "PATCH_VERIFIED_SECURE",
                "confidence": 98,
                "reason": "Reentrancy guard nonReentrant completely mitigates the vulnerability."
            })
        }
    }, vm=direct_vm)

    # Adjudicate
    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "SETTLED"
    assert b["verdict"] == "PATCH_VERIFIED_SECURE"
    assert b["auditor_payout"] == "12000"
    assert b["funder_refund"] == "0"
    assert "Reentrancy guard nonReentrant" in b["reason"]

    # Settled bounty cannot be adjudicated again
    with pytest.raises(Exception, match="Bounty must be in SUBMITTED state to adjudicate"):
        contract.adjudicate_patch(bid)


def test_adjudicate_patch_partial_coverage_50_percent_payout(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    direct_vm.value = 10000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/smart-audit/staking",
        vulnerability_details="Missing slippage check and unauthorized reward drain vulnerability",
        target_file_path="contracts/StakingRewards.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    patch_sha = "e5f6a1b2c3d40002"
    contract.submit_patch(bid, patch_sha)

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": "// Partially patched staking reward math"}
        },
        "llm_mocks": {
            ".*": json.dumps({
                "verdict": "PARTIAL_COVERAGE",
                "confidence": 85,
                "reason": "Slippage check added but unauthorized reward drain edge cases remain."
            })
        }
    }, vm=direct_vm)

    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "SETTLED"
    assert b["verdict"] == "PARTIAL_COVERAGE"
    assert b["auditor_payout"] == "5000"
    assert b["funder_refund"] == "5000"
    assert "Slippage check added" in b["reason"]


def test_adjudicate_patch_vulnerability_persists_resubmission(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    direct_vm.value = 6000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/smart-audit/oracle",
        vulnerability_details="Price manipulation vulnerability via unweighted spot price reading",
        target_file_path="contracts/PriceOracle.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    patch_sha = "badsha0000001"
    contract.submit_patch(bid, patch_sha)

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": "// Unchanged vulnerable oracle code"}
        },
        "llm_mocks": {
            ".*": json.dumps({
                "verdict": "VULNERABILITY_PERSISTS",
                "confidence": 95,
                "reason": "Spot price is still used without TWAP or liquidity sanity checks."
            })
        }
    }, vm=direct_vm)

    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    # Stays SUBMITTED, 0 payout
    assert b["status"] == "SUBMITTED"
    assert b["verdict"] == "VULNERABILITY_PERSISTS"
    assert b["auditor_payout"] == "0"
    assert b["funder_refund"] == "0"
    assert "Spot price is still used" in b["reason"]

    # Auditor can re-submit a refined patch SHA
    new_sha = "goodsha0000002"
    contract.submit_patch(bid, new_sha)

    b2 = json.loads(contract.get_bounty(bid))
    assert b2["patch_commit_sha"] == new_sha
    assert b2["status"] == "SUBMITTED"


def test_adjudicate_patch_github_offline_or_404(contract, direct_vm, direct_alice, direct_bob):
    direct_vm.sender = direct_alice
    direct_vm.value = 5000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/smart-audit/offline-test",
        vulnerability_details="Flawed token mint authorization vulnerability in admin module",
        target_file_path="contracts/TokenMinter.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    contract.submit_patch(bid, "deadbeef12345")

    # Web mock returns 404
    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 404, "body": "404: Not Found"}
        }
    }, vm=direct_vm)

    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "SUBMITTED"
    assert b["verdict"] == "VULNERABILITY_PERSISTS"
    assert "Patched file is offline, 404, or blank on GitHub" in b["reason"]


def test_cancel_expired_bounty_bounded_recovery(contract, direct_vm, direct_alice, direct_bob, direct_charlie):
    t_start = datetime(2026, 10, 16, 10, 0, 0, tzinfo=timezone.utc)
    direct_vm.warp(t_start.isoformat())

    direct_vm.sender = direct_alice
    direct_vm.value = 15000
    duration_days = 7

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/smart-audit/recovery",
        vulnerability_details="Unchecked return value in external bridge token transfer",
        target_file_path="contracts/Bridge.sol",
        duration_sec=86400 * duration_days
    )

    # 1. Non-funder attempts cancellation
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="Only project funder can cancel expired bounty"):
        contract.cancel_expired_bounty(bid)

    # 2. Premature cancellation before deadline
    direct_vm.sender = direct_alice
    with pytest.raises(Exception, match="Bounty deadline has not passed yet"):
        contract.cancel_expired_bounty(bid)

    # Warp past deadline (8 days later)
    direct_vm.warp((t_start + timedelta(days=duration_days + 1)).isoformat())

    # 3. Successful bounded cancellation & 100% refund
    contract.cancel_expired_bounty(bid)

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "CANCELLED"
    assert b["verdict"] == "VULNERABILITY_PERSISTS"
    assert b["auditor_payout"] == "0"
    assert b["funder_refund"] == "15000"
    assert "Bounty cancelled by funder" in b["reason"]

    # 4. Cannot cancel already cancelled bounty
    with pytest.raises(Exception, match="Bounty is already cancelled"):
        contract.cancel_expired_bounty(bid)

    # 5. Auditor cannot submit patch on cancelled bounty
    direct_vm.sender = direct_bob
    with pytest.raises(Exception, match="Bounty is cancelled"):
        contract.submit_patch(bid, "abcdef123456")


def test_adjudicate_patch_evaluates_code_beyond_4000_chars_full_file(contract, direct_vm, direct_alice, direct_bob):
    """Verifies that files >4000 chars are evaluated in full without silent prefix truncation."""
    direct_vm.sender = direct_alice
    direct_vm.value = 14000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/defi-protocol/large-vault",
        vulnerability_details="Reentrancy exploit in emergencyWithdrawAll located at bottom of contract",
        target_file_path="contracts/LargeVault.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    patch_sha = "longfilepatch001"
    contract.submit_patch(bid, patch_sha)

    # Construct a large Solidity contract (~6,500 characters)
    # The fix is deliberately located past character 4500 (line 140+)
    padding = "// Standard ERC20 and Vault logic padding\n" * 120  # ~5,000 chars
    large_patched_source = f"""
    contract LargeVault {{
        {padding}
        bool private _reentrancyLocked;
        modifier nonReentrant() {{
            require(!_reentrancyLocked, "LOCKED");
            _reentrancyLocked = true;
            _;
            _reentrancyLocked = false;
        }}
        function emergencyWithdrawAll() external nonReentrant {{
            uint256 amt = balances[msg.sender];
            balances[msg.sender] = 0;
            (bool ok, ) = msg.sender.call{{value: amt}}("");
            require(ok, "Transfer failed");
        }}
    }}
    """
    assert len(large_patched_source) > 5000

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": large_patched_source}
        },
        "llm_mocks": {
            ".*": json.dumps({
                "verdict": "PATCH_VERIFIED_SECURE",
                "confidence": 99,
                "reason": "Complete full file evaluated (6.5k chars); emergencyWithdrawAll properly protected."
            })
        }
    }, vm=direct_vm)

    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "SETTLED"
    assert b["verdict"] == "PATCH_VERIFIED_SECURE"
    assert b["auditor_payout"] == "14000"
    assert "Complete full file evaluated" in b["reason"]


def test_adjudicate_patch_detects_regression_beyond_4000_chars(contract, direct_vm, direct_alice, direct_bob):
    """Verifies that regressions located past char 4000 are not silently excluded."""
    direct_vm.sender = direct_alice
    direct_vm.value = 10000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/defi-protocol/regression-vault",
        vulnerability_details="Reentrancy flaw in withdraw, ensure no regressions introduced",
        target_file_path="contracts/RegressionVault.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    patch_sha = "regressionpatch002"
    contract.submit_patch(bid, patch_sha)

    # Fix at top, but backdoor/regression at bottom past char 4500
    padding = "// Normal vault helper methods and logic padding\n" * 160
    large_source_with_regression = f"""
    contract RegressionVault {{
        function withdraw() external {{
            // Fixed reentrancy at top
            balances[msg.sender] = 0;
        }}
        {padding}
        // REGRESSION INTRODUCED AT BOTTOM (PAST 4500 CHARS):
        function backdoorExecute(address target, bytes calldata data) external {{
            target.delegatecall(data); // Unprotected delegatecall regression!
        }}
    }}
    """
    assert len(large_source_with_regression) > 5000

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": large_source_with_regression}
        },
        "llm_mocks": {
            ".*": json.dumps({
                "verdict": "VULNERABILITY_PERSISTS",
                "confidence": 98,
                "reason": "Severe regression detected past char 4500: unprotected delegatecall backdoor."
            })
        }
    }, vm=direct_vm)

    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    # Stays SUBMITTED, 0 payout, security jury catches regression
    assert b["status"] == "SUBMITTED"
    assert b["verdict"] == "VULNERABILITY_PERSISTS"
    assert b["auditor_payout"] == "0"
    assert "backdoor" in b["reason"]


def test_adjudicate_patch_exceeding_max_bounded_file_size_fails_closed(contract, direct_vm, direct_alice, direct_bob):
    """Verifies that files > 48,000 chars fail-closed and strictly refuse silent omission."""
    direct_vm.sender = direct_alice
    direct_vm.value = 8000

    bid = contract.create_bounty(
        auditor=direct_bob,
        repo_url="https://github.com/defi-protocol/huge-monolith",
        vulnerability_details="Logic bypass in monolithic contract",
        target_file_path="contracts/Monolith.sol",
        duration_sec=86400 * 7
    )

    direct_vm.sender = direct_bob
    contract.submit_patch(bid, "hugemonolithsha")

    # Construct huge file (55,000 characters)
    huge_source = "// Huge code line\n" * 3000
    assert len(huge_source) > 48000

    sim_installMocks({
        "web_mocks": {
            ".*": {"status": 200, "body": huge_source}
        }
    }, vm=direct_vm)

    contract.adjudicate_patch(bid)

    b = json.loads(contract.get_bounty(bid))
    assert b["status"] == "SUBMITTED"
    assert b["verdict"] == "VULNERABILITY_PERSISTS"
    assert "exceeds bounded limit" in b["reason"]
    assert "Silent omission prohibited" in b["reason"]

