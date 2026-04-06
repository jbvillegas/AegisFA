import json
import os
import re
import torch
from typing import Dict, List, Any
from .service import load_model
from .openai_client import get_openai_client

class InsightsGenerator:
    
    SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.provider = os.getenv("INSIGHTS_LLM_PROVIDER", "openai").strip().lower()
        self.openai_model = os.getenv("INSIGHTS_OPENAI_MODEL", "gpt-4o-mini")
        self.allow_local_fallback = os.getenv("INSIGHTS_ALLOW_LOCAL_FALLBACK", "true").strip().lower() == "true"
    
    def _load_llm(self):
        if self.model is None or self.tokenizer is None:
            self.model, self.tokenizer = load_model()

    def _generate_with_openai(self, system_prompt: str, user_prompt: str, max_tokens: int = 512) -> str:

        client = get_openai_client()
        response = client.chat.completions.create(
            model=self.openai_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2, ## Lower temperature for more focused responses
            max_tokens=max_tokens,
        )
        return (response.choices[0].message.content or "").strip()
    
    def _generate_with_llm(self, system_prompt: str, user_prompt: str, max_tokens: int = 512) -> str:
        if self.provider == "openai":
            try:
                return self._generate_with_openai(system_prompt, user_prompt, max_tokens=max_tokens)
            except Exception:
                if not self.allow_local_fallback:
                    raise

        self._load_llm()
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer(text, return_tensors="pt")
        
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                temperature=0.3,
                do_sample=True,
                top_p=0.9,
                pad_token_id=self.tokenizer.eos_token_id
            )
        
        new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
        response = self.tokenizer.decode(new_tokens, skip_special_tokens=True)
        return response.strip()
    
    def generate_threat_insights(self, threats: List[Dict]) -> List[Dict]:
        #Args:
        #   threats: List of threat detection dictionaries
        #Returns:
        #   List of threat insights with recommendations
        insights = []
        
        for threat in threats:
            threat_type = threat.get("threat_type", "unknown")
            severity = threat.get("severity", "medium")
            description = threat.get("description", "")
            
            system_prompt = (
                "You are a cybersecurity expert. Convert the following threat detection into an actionable insight. "
                "Provide: 1) What happened, 2) Why it's a concern, 3) Immediate actions, 4) Long-term mitigation. "
                "Format as JSON with fields: summary, concern, immediate_actions (array), mitigation (array), "
                "risk_score (1-10), exploitability (low/medium/high)"
            )
            
            user_prompt = (
                f"Threat Type: {threat_type}\n"
                f"Severity: {severity}\n"
                f"Description: {description}\n"
                f"Analysis time: {threat.get('timestamp', 'unknown')}"
            )
            
            response = self._generate_with_llm(system_prompt, user_prompt, max_tokens=600)
            
            try:
                # Try to extract JSON from response
                json_match = re.search(r'(\{.*\})', response, re.DOTALL)
                if json_match:
                    insight = json.loads(json_match.group(1))
                else:
                    insight = self._parse_free_text_insight(response, threat_type, severity)
            except json.JSONDecodeError:
                insight = self._parse_free_text_insight(response, threat_type, severity)
            
            # Ensure required fields
            insight.update({
                "threat_type": threat_type,
                "original_severity": severity,
                "raw_response": response
            })
            
            insights.append(insight)
        
        return insights
    
    def generate_incident_summary(self, 
                                  threats: List[Dict],
                                  log_count: int = 0,
                                  correlation_data: Dict = None) -> Dict:
        #Generate executive summary from multiple threats.
        #Args: Threats: List of detected threats, log_count: Number of logs analyzed, correlation_data: Additional correlation data
        #Returns: Executive summary with risk assessment and recommended actions
        if not threats:
            return {
                "status": "no_threats",
                "summary": "No threats detected",
                "logs_analyzed": log_count,
                "risk_level": "low"
            }
        
        threat_summary = json.dumps([
            {
                "type": t.get("threat_type", "unknown"),
                "severity": t.get("severity", "medium")
            }
            for t in threats[:10]  # Limit to top 10 for context
        ], indent=2)
        
        system_prompt = (
            "You are a CISO preparing a brief incident summary for executives. "
            "Synthesize the threat data into: 1) What happened (1 sentence), "
            "2) Impact assessment, 3) Recommended immediate actions (top 3), "
            "4) Risk rating. Be concise and actionable. Format as JSON."
        )
        
        user_prompt = (
            f"Threat Summary:\n{threat_summary}\n"
            f"Total Logs Analyzed: {log_count}\n"
            f"Number of Threats: {len(threats)}"
        )
        
        response = self._generate_with_llm(system_prompt, user_prompt, max_tokens=700)
        
        try:
            json_match = re.search(r'(\{.*\})', response, re.DOTALL)
            if json_match:
                summary = json.loads(json_match.group(1))
            else:
                summary = {
                    "executive_summary": response,
                    "threat_count": len(threats),
                    "requires_manual_review": True
                }
        except json.JSONDecodeError:
            summary = {
                "executive_summary": response,
                "threat_count": len(threats),
                "requires_manual_review": True
            }
        
        # Calculate overall risk level
        risk_level = self._calculate_risk_level(threats)
        
        summary.update({
            "logs_analyzed": log_count,
            "threat_count": len(threats),
            "overall_risk_level": risk_level,
            "raw_response": response
        })
        
        return summary
    
    def generate_remediation_plan(self, threat: Dict) -> Dict:
        

        system_prompt = (
            "You are a cybersecurity incident response specialist. "
            "Create a detailed remediation plan for the threat. Include:\n"
            "- Immediate steps (0-1 hour)\n"
            "- Short term (1-24 hours)\n"
            "- Medium term (1-7 days)\n"
            "- Long term (1-3 months)\n"
            "Format as JSON with array of steps, each with: action, timeline, owner, priority"
        )
        
        user_prompt = (
            f"Threat Type: {threat.get('threat_type', 'unknown')}\n"
            f"Severity: {threat.get('severity', 'medium')}\n"
            f"Description: {threat.get('description', '')}\n"
            f"Affected Systems: {json.dumps(threat.get('affected_entries', []))}"
        )
        
        response = self._generate_with_llm(system_prompt, user_prompt, max_tokens=800)
        
        try:
            json_match = re.search(r'(\{.*\})', response, re.DOTALL)
            if json_match:
                plan = json.loads(json_match.group(1))
            else:
                plan = {"remediation_steps": response.split('\n')}
        except json.JSONDecodeError:
            plan = {"remediation_steps": response.split('\n')}
        
        plan.update({
            "threat_type": threat.get("threat_type", "unknown"),
            "severity": threat.get("severity", "medium")
        })
        
        return plan
    
    def generate_investigation_guide(self, log_classification: Dict, threats: List[Dict]) -> Dict:
        #Generate investigation guide based on log classification and detected threats.
        #Args: log_classification: Classification of the log source, threats: List of detected threats
        #Returns: Investigation guide with steps and focus areas
        system_prompt = (
            "You are a forensic analyst. Based on the log classification and threats, "
            "create an investigation guide. Include:\n"
            "- What to look for\n"
            "- Where to look\n"
            "- Questions to answer\n"
            "- Evidence to collect\n"
            "Format as JSON with key sections"
        )
        
        user_prompt = (
            f"Log Classification: {json.dumps(log_classification)}\n"
            f"Detected Threats: {json.dumps(threats[:5])}\n"
            f"Total Threats: {len(threats)}"
        )
        
        response = self._generate_with_llm(system_prompt, user_prompt, max_tokens=700)
        
        try:
            json_match = re.search(r'(\{.*\})', response, re.DOTALL)
            if json_match:
                guide = json.loads(json_match.group(1))
            else:
                guide = {"investigation_steps": response}
        except json.JSONDecodeError:
            guide = {"investigation_steps": response}
        
        return guide
    
    def _parse_free_text_insight(self, text: str, threat_type: str, severity: str) -> Dict:
 
        return {
            "summary": text[:200],
            "full_response": text,
            "threat_type": threat_type,
            "severity": severity,
            "requires_manual_review": True
        }
    
    def _calculate_risk_level(self, threats: List[Dict]) -> str:
        """Calculate overall risk level from threats."""
        if not threats:
            return "low"
        
        severity_scores = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        
        max_score = max(
            severity_scores.get(t.get("severity", "medium"), 2) 
            for t in threats
        )
        
        critical_count = sum(1 for t in threats if t.get("severity") == "critical")
        
        if critical_count > 0:
            return "critical"
        elif max_score >= 3:
            return "high"
        elif max_score >= 2:
            return "medium"
        else:
            return "low"

## must stay outside of the class to avoid circular imports
def get_insights_generator() -> InsightsGenerator: 
    """Get or create a global InsightsGenerator instance."""
    return InsightsGenerator()
