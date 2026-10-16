# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
from dataclasses import dataclass
import json


try:
    gl.UserError = gl.vm.UserError
except Exception:
    pass


def _addr_str(addr: Address) -> str:
    """Safely format an Address instance into a lowercase hex string."""
    try:
        return addr.as_hex.lower()
    except Exception:
        return str(addr).lower()


def _get_sender() -> Address:
    """Safely obtain transaction sender across GenVM runtime versions."""
    try:
        if hasattr(gl, "message"):
            if hasattr(gl.message, "sender"):
                return gl.message.sender
            if hasattr(gl.message, "sender_address"):
                return gl.message.sender_address
    except Exception:
        pass
    try:
        if hasattr(gl, "message_raw") and isinstance(gl.message_raw, dict):
            sender_raw = gl.message_raw.get("from") or gl.message_raw.get("sender")
            if sender_raw:
                return Address(str(sender_raw))
    except Exception:
        pass
    return Address("0x0000000000000000000000000000000000000000")


def _safe_transfer(recipient: Address, amount: bigint) -> None:
    """Safely disburse native GEN to an address using official GenLayer SDK pattern."""
    if amount <= bigint(0):
        return
    gl.get_contract_at(recipient).emit_transfer(value=u256(int(amount)))


def _clean_path(path_str: str) -> str:
    """Normalize file path and prevent directory traversal."""
    p = path_str.strip().replace("\\", "/").strip("/")
    if ".." in p or p.startswith("./"):
        raise gl.UserError("Invalid relative path components ('..' or './') in file path.")
    return p


def _parse_canonical_repo(repo_url: str) -> tuple[str, str]:
    """Extract and validate canonical owner and repository name from GitHub URL."""
    clean = repo_url.strip()
    if "?" in clean:
        clean = clean.split("?")[0]
    if "#" in clean:
        clean = clean.split("#")[0]
    clean = clean.strip()

    if clean.startswith("https://"):
        rest = clean[8:]
    elif clean.startswith("http://"):
        rest = clean[7:]
    else:
        raise gl.UserError("URL must begin with http:// or https://")

    parts = rest.split("/", 1)
    host = parts[0].strip().lower()
    path = parts[1].strip() if len(parts) > 1 else ""

    if host not in ("github.com", "www.github.com"):
        raise gl.UserError(f"Host must be authoritative github.com, got: {host}")

    segments = [s.strip() for s in path.strip("/").split("/") if s.strip()]
    if len(segments) < 2:
        raise gl.UserError("Invalid repository URL format. Expected: https://github.com/<owner>/<repo>")

    owner = segments[0].lower()
    repo = segments[1].lower()
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise gl.UserError("Repository owner and name must not be empty.")

    return owner, repo


@allow_storage
@dataclass
class AuditBounty:
    bounty_id: str
    project_funder: Address
    auditor: Address
    repo_url: str                 # Authoritative repo URL (e.g. https://github.com/org/repo)
    vulnerability_details: str    # Description of security flaw (e.g. Reentrancy in withdraw())
    target_file_path: str         # File path where flaw exists
    patch_commit_sha: str         # Commit hash containing the fix
    bounty_reward: bigint         # Locked escrow reward
    auditor_payout: bigint
    funder_refund: bigint
    status: str                   # "CREATED", "SUBMITTED", "SETTLED", "CANCELLED"
    verdict: str                  # "PENDING", "PATCH_VERIFIED_SECURE", "PARTIAL_COVERAGE", "VULNERABILITY_PERSISTS"
    reason: str                   # Consensus reasoning
    deadline: bigint              # Submission cutoff timestamp
    created_at: bigint
    resolved_at: bigint


class Contract(gl.Contract):
    """
    SmartContractAuditBountyX: Autonomous Vulnerability Fix & Proof-of-Patch Escrow Protocol
    Track: Autonomous Protocols / Future of Work
    """
    owner: Address
    bounty_count: bigint
    bounties: TreeMap[str, AuditBounty]

    def __init__(self):
        # GenVM automatically initializes TreeMap storage fields to empty.
        self.owner = _get_sender()
        self.bounty_count = bigint(0)

    def _get_current_timestamp(self) -> bigint:
        """Derive trusted deterministic execution timestamp from GenLayer transaction context."""
        try:
            from datetime import datetime
            dt_raw = getattr(gl.message, "datetime", None)
            if dt_raw is None and hasattr(gl, "message_raw") and isinstance(gl.message_raw, dict):
                dt_raw = gl.message_raw.get("datetime")
            if dt_raw:
                dt_str = str(dt_raw).strip().replace("Z", "+00:00")
                dt = datetime.fromisoformat(dt_str)
                ts = int(dt.timestamp())
                if ts > 0:
                    return bigint(ts)
        except Exception:
            pass

        try:
            if hasattr(gl, "block") and hasattr(gl.block, "timestamp"):
                ts = int(gl.block.timestamp)
                if ts > 0:
                    return bigint(ts)
        except Exception:
            pass

        return bigint(0)

    def _parse_llm_json(self, text: str) -> dict:
        """Safely parse LLM responses, stripping markdown wrappers if present."""
        try:
            cleaned = str(text).strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            elif cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            return json.loads(cleaned.strip())
        except Exception as e:
            return {
                "verdict": "VULNERABILITY_PERSISTS",
                "confidence": 0,
                "reason": f"Failed to parse LLM JSON: {str(e)[:100]}"
            }

    @gl.public.write.payable
    def create_bounty(
        self,
        auditor: Address,
        repo_url: str,
        vulnerability_details: str,
        target_file_path: str,
        duration_sec: int
    ) -> str:
        """
        Project funder locks bounty rewards into escrow for a designated security auditor / white-hat.
        """
        deposit = bigint(gl.message.value)
        if deposit <= bigint(0):
            raise gl.UserError("Bounty reward must be greater than 0 GEN.")

        owner_name, repo_name = _parse_canonical_repo(repo_url)
        canonical_repo = f"https://github.com/{owner_name}/{repo_name}"

        clean_vuln = vulnerability_details.strip()
        clean_path = _clean_path(target_file_path)

        if len(clean_vuln) < 15:
            raise gl.UserError("vulnerability_details must be comprehensive (min 15 characters).")
        if len(clean_path) < 2:
            raise gl.UserError("target_file_path is required.")

        if _addr_str(_get_sender()) == _addr_str(auditor):
            raise gl.UserError("Funder and auditor cannot be the same address.")

        now_ts = self._get_current_timestamp()
        duration = bigint(duration_sec if duration_sec >= 86400 else 86400)
        deadline = now_ts + duration if now_ts > bigint(0) else bigint(86400 * 14)

        self.bounty_count += bigint(1)
        bid = str(self.bounty_count)

        self.bounties[bid] = AuditBounty(
            bounty_id=bid,
            project_funder=_get_sender(),
            auditor=auditor,
            repo_url=canonical_repo,
            vulnerability_details=clean_vuln,
            target_file_path=clean_path,
            patch_commit_sha="",
            bounty_reward=deposit,
            auditor_payout=bigint(0),
            funder_refund=bigint(0),
            status="CREATED",
            verdict="PENDING",
            reason="Bounty locked in escrow. Awaiting fix commit SHA from auditor.",
            deadline=deadline,
            created_at=self.bounty_count,
            resolved_at=bigint(0)
        )

        return bid

    @gl.public.write
    def submit_patch(self, bounty_id: str, patch_commit_sha: str) -> None:
        """
        Auditor submits the canonical git commit SHA containing the security patch.
        Can be used to correct the patch if previous adjudication returned partial/insufficient data.
        """
        if bounty_id not in self.bounties:
            raise gl.UserError("Bounty not found.")

        bounty = self.bounties[bounty_id]
        if _addr_str(_get_sender()) != _addr_str(bounty.auditor):
            raise gl.UserError("Only designated auditor can submit patch.")

        if bounty.status == "SETTLED":
            raise gl.UserError("Bounty is already settled.")
        if bounty.status == "CANCELLED":
            raise gl.UserError("Bounty is cancelled.")

        now_ts = self._get_current_timestamp()
        if now_ts > bigint(0) and now_ts > bounty.deadline:
            raise gl.UserError("Bounty submission deadline has passed.")

        clean_sha = patch_commit_sha.strip().lower()
        if len(clean_sha) < 7:
            raise gl.UserError("Invalid commit SHA format.")

        bounty.patch_commit_sha = clean_sha
        bounty.status = "SUBMITTED"
        bounty.reason = f"Patch commit {clean_sha} submitted. Ready for autonomous AI audit."
        self.bounties[bounty_id] = bounty

    @gl.public.write
    def cancel_expired_bounty(self, bounty_id: str) -> None:
        """
        Bounded Safe Recovery Path:
        If deadline has elapsed without a verified patch settlement (never submitted or patch failed),
        funder safely reclaims 100% of escrowed reward.
        """
        if bounty_id not in self.bounties:
            raise gl.UserError("Bounty not found.")

        bounty = self.bounties[bounty_id]
        if _addr_str(_get_sender()) != _addr_str(bounty.project_funder):
            raise gl.UserError("Only project funder can cancel expired bounty.")

        if bounty.status == "SETTLED":
            raise gl.UserError("Bounty is already settled.")
        if bounty.status == "CANCELLED":
            raise gl.UserError("Bounty is already cancelled.")

        now_ts = self._get_current_timestamp()
        if now_ts > bigint(0) and now_ts <= bounty.deadline:
            raise gl.UserError("Bounty deadline has not passed yet.")

        refund_val = bounty.bounty_reward
        bounty.status = "CANCELLED"
        bounty.verdict = "VULNERABILITY_PERSISTS"
        bounty.auditor_payout = bigint(0)
        bounty.funder_refund = refund_val
        bounty.reason = "Bounty cancelled by funder after submission deadline elapsed without verified fix."
        bounty.resolved_at = self.bounty_count
        self.bounties[bounty_id] = bounty

        if refund_val > bigint(0):
            _safe_transfer(bounty.project_funder, refund_val)

    @gl.public.write
    def adjudicate_patch(self, bounty_id: str) -> None:
        """
        Validators inspect the patched file directly from authoritative GitHub raw host,
        evaluate AST changes and vulnerability mitigation, and execute deterministic payouts.
        """
        if bounty_id not in self.bounties:
            raise gl.UserError("Bounty not found.")

        bounty = self.bounties[bounty_id]
        if bounty.status != "SUBMITTED":
            raise gl.UserError("Bounty must be in SUBMITTED state to adjudicate.")

        owner_name, repo_name = _parse_canonical_repo(bounty.repo_url)
        raw_patch_url = f"https://raw.githubusercontent.com/{owner_name}/{repo_name}/{bounty.patch_commit_sha}/{bounty.target_file_path}"
        vuln_local = str(bounty.vulnerability_details)
        file_path_local = str(bounty.target_file_path)

        def leader_fn():
            patched_code = ""
            try:
                res = gl.nondet.web.render(raw_patch_url, mode="text")
                patched_code = res.content if hasattr(res, "content") else str(res)
            except Exception:
                patched_code = ""

            lower_code = patched_code[:500].lower() if patched_code else ""
            if len(patched_code.strip()) < 20 or "404 not found" in lower_code:
                return {
                    "verdict": "VULNERABILITY_PERSISTS",
                    "confidence": 100,
                    "reason": "Patched file is offline, 404, or blank on GitHub."
                }

            snippet = patched_code[:4000]

            prompt = f"""You are an Objective Smart Contract Security Auditor and Proof-of-Patch Arbiter on GenLayer.
Evaluate whether the code at the submitted commit successfully neutralizes the declared vulnerability.

TARGET FILE: {file_path_local}
REPORTED VULNERABILITY:
\"\"\"
{vuln_local}
\"\"\"

PATCHED SOURCE CODE (from GitHub Raw commit {raw_patch_url}):
\"\"\"
{snippet}
\"\"\"

AUDIT EVALUATION RUBRIC:
Classify into strictly ONE of the discrete verdicts:
- "PATCH_VERIFIED_SECURE": The patch completely mitigates the security flaw (e.g., proper checks-effects-interactions, reentrancy guards, safe math, access control) without introducing regressions.
- "PARTIAL_COVERAGE": The patch addresses part of the attack vector but leaves edge cases open or implements an incomplete mitigation.
- "VULNERABILITY_PERSISTS": The vulnerability is still exploitable, the file is unchanged, or the fix is superficial/cosmetic.

OUTPUT FORMAT:
Respond ONLY with a VALID JSON object (no markdown, no backticks):
{{
  "verdict": "PATCH_VERIFIED_SECURE" | "PARTIAL_COVERAGE" | "VULNERABILITY_PERSISTS",
  "confidence": <integer from 0 to 100>,
  "reason": "<concise explanation max 220 characters>"
}}"""

            try:
                raw_res = gl.nondet.exec_prompt(prompt, response_format="json")
                parsed = None
                if isinstance(raw_res, dict):
                    parsed = raw_res
                elif hasattr(raw_res, "content") and isinstance(raw_res.content, dict):
                    parsed = raw_res.content
                else:
                    text = raw_res.content if hasattr(raw_res, "content") else str(raw_res)
                    cleaned = str(text).strip()
                    if cleaned.startswith("```json"):
                        cleaned = cleaned[7:]
                    elif cleaned.startswith("```"):
                        cleaned = cleaned[3:]
                    if cleaned.endswith("```"):
                        cleaned = cleaned[:-3]
                    parsed = json.loads(cleaned.strip())

                verdict_candidate = str(parsed.get("verdict", "VULNERABILITY_PERSISTS")).strip().upper()
                valid_verdicts = ("PATCH_VERIFIED_SECURE", "PARTIAL_COVERAGE", "VULNERABILITY_PERSISTS")
                if verdict_candidate not in valid_verdicts:
                    verdict_candidate = "VULNERABILITY_PERSISTS"

                try:
                    conf = int(parsed.get("confidence", 0))
                    conf = max(0, min(100, conf))
                except Exception:
                    conf = 50

                reason_str = str(parsed.get("reason", "Patch evaluated by autonomous security jury."))[:220]

                return {
                    "verdict": verdict_candidate,
                    "confidence": conf,
                    "reason": reason_str
                }
            except Exception as e:
                return {
                    "verdict": "VULNERABILITY_PERSISTS",
                    "confidence": 0,
                    "reason": f"Evaluation error: {str(e)[:100]}"
                }

        def validator_fn(leader_res) -> bool:
            if not isinstance(leader_res, gl.vm.Return):
                return False
            leader = leader_res.calldata
            if not isinstance(leader, dict) or "verdict" not in leader:
                return False

            valid_verdicts = ("PATCH_VERIFIED_SECURE", "PARTIAL_COVERAGE", "VULNERABILITY_PERSISTS")
            l_verdict = str(leader.get("verdict", "")).strip().upper()
            if l_verdict not in valid_verdicts:
                return False

            mine = leader_fn()
            m_verdict = str(mine.get("verdict", "")).strip().upper()

            # DISCRETE EQUIVALENCE: 100% agreement on exact security verdict
            return l_verdict == m_verdict

        adjudication_res = gl.vm.run_nondet(leader_fn, validator_fn)
        if isinstance(adjudication_res, dict):
            final_res = adjudication_res
        else:
            final_res = self._parse_llm_json(str(adjudication_res))

        verdict = str(final_res.get("verdict", "VULNERABILITY_PERSISTS")).strip().upper()
        valid_verdicts = ("PATCH_VERIFIED_SECURE", "PARTIAL_COVERAGE", "VULNERABILITY_PERSISTS")
        if verdict not in valid_verdicts:
            verdict = "VULNERABILITY_PERSISTS"

        reason = str(final_res.get("reason", "Consensus concluded."))

        total_bounty = bounty.bounty_reward

        if verdict == "PATCH_VERIFIED_SECURE":
            # 100% payout to auditor
            bounty.status = "SETTLED"
            bounty.verdict = verdict
            bounty.auditor_payout = total_bounty
            bounty.funder_refund = bigint(0)
            bounty.reason = reason
            bounty.resolved_at = self.bounty_count
            self.bounties[bounty_id] = bounty
            _safe_transfer(bounty.auditor, total_bounty)

        elif verdict == "PARTIAL_COVERAGE":
            # 50% payout to auditor, 50% refund to project
            auditor_share = total_bounty // bigint(2)
            funder_share = total_bounty - auditor_share
            bounty.status = "SETTLED"
            bounty.verdict = verdict
            bounty.auditor_payout = auditor_share
            bounty.funder_refund = funder_share
            bounty.reason = reason
            bounty.resolved_at = self.bounty_count
            self.bounties[bounty_id] = bounty
            _safe_transfer(bounty.auditor, auditor_share)
            _safe_transfer(bounty.project_funder, funder_share)

        else:
            # Vulnerability persists: Keep in SUBMITTED state so auditor can update commit before deadline,
            # or funder can cancel when deadline expires.
            bounty.verdict = verdict
            bounty.reason = reason
            self.bounties[bounty_id] = bounty

    @gl.public.view
    def get_bounty(self, bounty_id: str) -> str:
        """Retrieve details of an audit bounty as a JSON string."""
        if bounty_id not in self.bounties:
            raise gl.UserError("Bounty not found.")
        b = self.bounties[bounty_id]
        return json.dumps({
            "bounty_id": b.bounty_id,
            "project_funder": _addr_str(b.project_funder),
            "auditor": _addr_str(b.auditor),
            "repo_url": b.repo_url,
            "vulnerability_details": b.vulnerability_details,
            "target_file_path": b.target_file_path,
            "patch_commit_sha": b.patch_commit_sha,
            "bounty_reward": str(b.bounty_reward),
            "auditor_payout": str(b.auditor_payout),
            "funder_refund": str(b.funder_refund),
            "status": b.status,
            "verdict": b.verdict,
            "reason": b.reason,
            "deadline": str(b.deadline),
            "created_at": str(b.created_at),
            "resolved_at": str(b.resolved_at)
        })

    @gl.public.view
    def get_current_time(self) -> int:
        """Retrieve current contract execution timestamp."""
        return int(str(self._get_current_timestamp()))

    @gl.public.view
    def get_bounty_count(self) -> int:
        return int(self.bounty_count)

    @gl.public.view
    def get_owner(self) -> str:
        return _addr_str(self.owner)
