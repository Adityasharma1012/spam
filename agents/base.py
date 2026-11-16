"""Abstract Base Agent class defining the multi-agent deliberation protocol."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple

from core.models import (
    AgentReport,
    AvailabilityStatus,
    DebateMessage,
    EvidenceItem,
)


class BaseAgent(ABC):
    """Abstract base class for threat detection agents."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    @abstractmethod
    def check_availability(self) -> Tuple[AvailabilityStatus, Optional[str]]:
        """Check whether the agent is available, degraded, or unavailable."""
        pass

    @abstractmethod
    async def analyze_round1(
        self,
        parsed_metadata: Dict[str, Any],
        evidence: List[EvidenceItem],
    ) -> AgentReport:
        """Perform Round 1 independent evaluation based strictly on parsed evidence."""
        pass

    @abstractmethod
    async def analyze_round2(
        self,
        parsed_metadata: Dict[str, Any],
        evidence: List[EvidenceItem],
        round1_reports: List[AgentReport],
        debate_messages: List[DebateMessage],
    ) -> AgentReport:
        """Perform Round 2 evaluation with structured sanitized findings from other agents.
        
        Never receives raw untrusted email text from other agents.
        """
        pass
