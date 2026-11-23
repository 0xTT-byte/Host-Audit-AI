import hashlib
from typing import Literal, Optional
from pydantic import BaseModel, Field, computed_field


class Finding(BaseModel):
    rule_id: str
    domain: Literal["exposure", "ssh", "containers", "privesc", "ioc"]
    title: str
    target: str
    evidence: str
    why_it_matters: str
    verify_cmd: str
    remediation_hint: str

    # Scoring factors (1 to 3)
    reachability: int = Field(ge=1, le=3, description="1=local/authenticated, 2=adjacent/container, 3=unauthenticated/network")
    privilege_gain: int = Field(ge=1, le=3, description="1=info/low priv, 2=service user/lateral, 3=root/host escape")
    ease: int = Field(ge=1, le=3, description="1=complex/unreliable, 2=standard exploit/tool, 3=trivial/misconfig")

    raw_context: Optional[str] = None

    @computed_field
    @property
    def priority_score(self) -> int:
        return self.reachability * self.privilege_gain * self.ease

    @computed_field
    @property
    def severity(self) -> Literal["critical", "high", "medium", "low"]:
        score = self.priority_score
        if score >= 18:
            return "critical"
        if score >= 12:
            return "high"
        if score >= 6:
            return "medium"
        return "low"

    @computed_field
    @property
    def finding_id(self) -> str:
        raw = f"{self.rule_id}|{self.target}|{self.evidence.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AttackChain(BaseModel):
    name: str = Field(description="Short descriptive name for the chained attack vector")
    severity: Literal["critical", "high", "medium", "low"]
    involved_rule_ids: list[str] = Field(description="Deterministic finding rule IDs comprising this chain")
    steps: list[str] = Field(description="Realistic sequential steps an attacker would follow")
    verify_cmds: list[str] = Field(description="Non-destructive commands to confirm each prerequisite step")
    fix_commands: list[str] = Field(description="Specific remediation commands to break the attack sequence")


class TriageReport(BaseModel):
    executive_summary: str = Field(description="Concise 2-3 sentence overview of host risk posture")
    attack_chains: list[AttackChain] = Field(default_factory=list, description="Synthesized multi-stage attack scenarios")
    false_positive_checks: list[str] = Field(default_factory=list, description="Guidance to filter benign operational exceptions")
