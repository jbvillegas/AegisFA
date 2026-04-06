"""
Integration module combining log classification and insights generation.
Provides high-level functions for the complete threat analysis pipeline.
"""

from typing import Dict, List, Any
from .log_classifier import get_classifier
from .insights_generator import get_insights_generator
from .threat_analysis import analyze_threats

class ThreatAnalysisPipeline:
    """Complete threat analysis pipeline combining classification and insights."""
    
    def __init__(self):
        self.classifier = get_classifier()
        self.insights_gen = get_insights_generator()
    
    def analyze_logs(self, logs: List[Dict], source_type: str) -> Dict:
        """
        Complete analysis: classify logs, detect threats, generate insights.
        
        Args:
            logs: List of normalized log entries
            source_type: Type of log source (auth, firewall, windows, etc.)
        
        Returns:
            Comprehensive analysis results
        """
        analysis_result = {
            "status": "completed",
            "logs_analyzed": len(logs),
            "source_type": source_type,
            "phases": {}
        }
        
        # Phase 1: Log Classification
        classification_results = self.classifier.classify_batch(logs)
        confidence_values = [
            r.get("confidence", 0.0)
            for r in classification_results
            if isinstance(r, dict)
        ]
        analysis_result["phases"]["classification"] = {
            "total": len(classification_results),
            "by_category": self._group_by_category(classification_results),
            "average_confidence": (
                sum(confidence_values) / len(confidence_values)
                if confidence_values else 0.0
            ),
            "details": classification_results[:50]  # Top 50 for API response
        }
        
        # Phase 2: Threat Detection
        threats = analyze_threats(logs, source_type)
        analysis_result["phases"]["threat_detection"] = {
            "threats_found": len(threats),
            "by_severity": self._group_by_severity(threats),
            "details": threats
        }
        
        # Phase 3: Insights Generation
        if threats:
            insights = self.insights_gen.generate_threat_insights(threats)
            incident_summary = self.insights_gen.generate_incident_summary(
                threats, 
                log_count=len(logs)
            )
            investigation_guide = self.insights_gen.generate_investigation_guide(
                analysis_result["phases"]["classification"],
                threats,
            )
            
            analysis_result["phases"]["insights"] = {
                "insights": insights[:20],  # Top 20 for response
                "incident_summary": incident_summary,
                "investigation_guide": investigation_guide,
            }
        
        return analysis_result
    
    def get_detailed_threat_analysis(self, threat: Dict) -> Dict:
        """
        Get detailed analysis for a specific threat.
        
        Args:
            threat: Threat detection dictionary
        
        Returns:
            Detailed threat analysis with remediation
        """
        insight = self.insights_gen.generate_threat_insights([threat])
        remediation = self.insights_gen.generate_remediation_plan(threat)
        
        return {
            "threat": threat,
            "insights": insight[0] if insight else {},
            "remediation_plan": remediation
        }
    
    def train_classifier(self, training_data: List[tuple]) -> Dict:
        """
        Train the RF classifier with labeled data.
        
        Args:
            training_data: List of (log_dict, category) tuples
        
        Returns:
            Training results
        """
        return self.classifier.train(training_data)
    
    def _group_by_category(self, classifications: List[Dict]) -> Dict[str, int]:
        """Group classifications by category."""
        grouping = {}
        for result in classifications:
            category = result.get("category", "unknown")
            grouping[category] = grouping.get(category, 0) + 1
        return grouping
    
    def _group_by_severity(self, threats: List[Dict]) -> Dict[str, int]:
        """Group threats by severity level."""
        grouping = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        for threat in threats:
            severity = threat.get("severity", "medium")
            if severity in grouping:
                grouping[severity] += 1
        return grouping


def get_pipeline() -> ThreatAnalysisPipeline:
    """Get or create a global ThreatAnalysisPipeline instance."""
    return ThreatAnalysisPipeline()
