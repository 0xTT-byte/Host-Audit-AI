import hashlib
from typing import Literal, Optional
from pydantic import BaseModel, Field, computed_field 

class Findings(BaseModel):
    rule_id: str
    domain: Literal["exposure", "ssh", "containers", "privesc", "ioc"]
    title: str 
    target: str
    evidence: str
    why_it_matters: str 
    verify_cmd: str 
    remediation_hint: str 
    
    # Scoring factors (1 to 3)
    reachability: int = Field(ge=1, le=3)
    privilege_gain: int = Field(ge=1, le=3)
    ease: int = Field(ge=1, le=3)
    
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
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    