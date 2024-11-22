import logging
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, Any, List, Optional
import smtplib
from email.mime.text import MIMEText
import json
from collections import defaultdict

class AISecurityMonitor:
    def __init__(
        self,
        model_name: str,
        alert_settings: Dict[str, Any],
        logging_path: Optional[str] = None
    ):
        """
        Initialize security monitor with alert capabilities
        
        Args:
            model_name: Name of the model being protected
            alert_settings: Dictionary containing alert configuration
                {
                    "email_recipients": list of security team email addresses,
                    "smtp_settings": SMTP server configuration,
                    "alert_thresholds": {
                        "max_requests_per_minute": int,
                        "suspicious_pattern_threshold": float,
                        "failed_attempts_threshold": int
                    }
                }
        """
        self.model_name = model_name
        self.alert_settings = alert_settings
        self.incident_log = []
        self.request_history = defaultdict(list)  # IP address -> list of timestamps
        
        # Configure logging
        logging.basicConfig(
            filename=logging_path or f"security_{model_name}_{datetime.now():%Y%m%d}.log",
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def detect_threat(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze request for potential security threats
        """
        threat_assessment = {
            "timestamp": datetime.now().isoformat(),
            "severity": "low",
            "threats_detected": [],
            "details": {}
        }
        
        # Check request rate
        if self._check_rate_limit(request_data["ip_address"]):
            threat_assessment["threats_detected"].append("rate_limit_exceeded")
            threat_assessment["severity"] = "medium"
        
        # Check input patterns
        pattern_check = self._analyze_input_patterns(request_data["input_data"])
        if pattern_check["suspicious_patterns"]:
            threat_assessment["threats_detected"].extend(pattern_check["suspicious_patterns"])
            threat_assessment["severity"] = "high"
            threat_assessment["details"]["patterns"] = pattern_check
        
        # Log the threat assessment
        if threat_assessment["threats_detected"]:
            self._log_incident(threat_assessment, request_data)
        
        return threat_assessment
    
    def _check_rate_limit(self, ip_address: str) -> bool:
        """
        Check if request rate from IP exceeds threshold
        """
        current_time = datetime.now()
        recent_requests = [
            timestamp for timestamp in self.request_history[ip_address]
            if current_time - timestamp < timedelta(minutes=1)
        ]
        
        # Update request history
        self.request_history[ip_address] = recent_requests + [current_time]
        
        return len(recent_requests) > self.alert_settings["alert_thresholds"]["max_requests_per_minute"]
    
    def _analyze_input_patterns(self, input_data: Any) -> Dict[str, Any]:
        """
        Analyze input for suspicious patterns
        """
        result = {
            "suspicious_patterns": [],
            "details": {}
        }
        
        try:
            input_array = np.asarray(input_data)
            
            # Check for extreme values
            if np.any(np.abs(input_array) > 1e6):
                result["suspicious_patterns"].append("extreme_values")
            
            # Check for unusual sparsity
            sparsity = np.count_nonzero(input_array) / input_array.size
            if sparsity < 0.01:
                result["suspicious_patterns"].append("suspicious_sparsity")
            
            # Check for repeating patterns
            if len(input_array.shape) > 1:
                gradient = np.gradient(input_array.astype(float))
                if np.all(np.abs(gradient) > 100):
                    result["suspicious_patterns"].append("potential_adversarial_pattern")
            
        except Exception as e:
            logging.error(f"Pattern analysis error: {str(e)}")
            result["suspicious_patterns"].append("analysis_error")
        
        return result
    
    def _log_incident(self, threat_assessment: Dict[str, Any], request_data: Dict[str, Any]) -> None:
        """
        Log security incident and send alerts if needed
        """
        incident = {
            "timestamp": threat_assessment["timestamp"],
            "severity": threat_assessment["severity"],
            "threats": threat_assessment["threats_detected"],
            "ip_address": request_data["ip_address"],
            "details": threat_assessment["details"]
        }
        
        # Log to file
        logging.warning(f"Security incident detected: {json.dumps(incident)}")
        
        # Store in incident history
        self.incident_log.append(incident)
        
        # Send alert if severity warrants it
        if threat_assessment["severity"] in ["medium", "high"]:
            self._send_alert(incident)
    
    def _send_alert(self, incident: Dict[str, Any]) -> None:
        """
        Send alert to security team
        """
        try:
            subject = f"Security Alert: {self.model_name} - {incident['severity'].upper()} Severity"
            body = f"""
Security incident detected:
-------------------------
Timestamp: {incident['timestamp']}
Severity: {incident['severity']}
Threats Detected: {', '.join(incident['threats'])}
IP Address: {incident['ip_address']}

Details:
{json.dumps(incident['details'], indent=2)}

Please review the incident and take appropriate action.
"""
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.alert_settings["smtp_settings"]["sender"]
            msg['To'] = ', '.join(self.alert_settings["email_recipients"])
            
            # Send email
            with smtplib.SMTP(
                self.alert_settings["smtp_settings"]["server"],
                self.alert_settings["smtp_settings"]["port"]
            ) as server:
                if self.alert_settings["smtp_settings"].get("use_tls"):
                    server.starttls()
                if "username" in self.alert_settings["smtp_settings"]:
                    server.login(
                        self.alert_settings["smtp_settings"]["username"],
                        self.alert_settings["smtp_settings"]["password"]
                    )
                server.send_message(msg)
                
        except Exception as e:
            logging.error(f"Failed to send alert: {str(e)}")
    
    def get_incident_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get summary of recent security incidents
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_incidents = [
            incident for incident in self.incident_log
            if datetime.fromisoformat(incident["timestamp"]) > cutoff_time
        ]
        
        return {
            "total_incidents": len(recent_incidents),
            "by_severity": {
                severity: len([i for i in recent_incidents if i["severity"] == severity])
                for severity in ["low", "medium", "high"]
            },
            "unique_ips": len(set(incident["ip_address"] for incident in recent_incidents)),
            "most_common_threats": self._get_common_threats(recent_incidents)
        }
    
    def _get_common_threats(self, incidents: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Get count of most common threat types
        """
        threat_counts = defaultdict(int)
        for incident in incidents:
            for threat in incident["threats"]:
                threat_counts[threat] += 1
        return dict(sorted(threat_counts.items(), key=lambda x: x[1], reverse=True))