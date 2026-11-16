"""Consensus module for Email Threat Detection Platform."""
from consensus.decision_table import DECISION_TABLE, DecisionRule
from consensus.engine import ThreatInvestigationEngine

__all__ = ["DECISION_TABLE", "DecisionRule", "ThreatInvestigationEngine"]
