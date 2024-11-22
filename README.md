# ai-security-alerts
Security monitoring system that logs suspicious activities and alerts your security team, allowing you to make informed decisions about escalating genuine threats.

Written by: DeWitt Gibson https://linkedin.com/in/dewitt-gibson/

# AI Model Security Monitor

Real-time security monitoring and team alert system for AI model deployments. Detects threats, alerts security teams, and logs suspicious activities.

## Features

- Real-time threat detection
- Automatic security team notifications
- Rate limiting and pattern analysis
- Incident logging and reporting
- IP-based monitoring
- Request pattern analysis
- Configurable alert thresholds
- SMTP email notifications

## Installation

```bash
pip install -r requirements.txt
```

Required dependencies in requirements.txt:
```
numpy>=1.21.0
typing>=3.7.4
smtplib
email
datetime
logging
```

## Usage

```python
from ai_security_monitor import AISecurityMonitor

# Initialize monitor
monitor = AISecurityMonitor(
    model_name="production_model",
    alert_settings={
        "email_recipients": ["security@company.com"],
        "smtp_settings": {
            "server": "smtp.company.com",
            "port": 587,
            "sender": "ai-alerts@company.com",
            "use_tls": True,
            "username": "alert_system",
            "password": "your_secure_password"
        },
        "alert_thresholds": {
            "max_requests_per_minute": 100,
            "suspicious_pattern_threshold": 0.8,
            "failed_attempts_threshold": 5
        }
    }
)

# Monitor requests
threat_assessment = monitor.detect_threat({
    "ip_address": request.remote_addr,
    "input_data": model_input,
    "timestamp": datetime.now()
})

# Get incident summary
summary = monitor.get_incident_summary(hours=24)
```

## Configuration

### Environment Variables
```bash
SMTP_SERVER=smtp.company.com
SMTP_PORT=587
ALERT_SENDER=ai-alerts@company.com
ALERT_RECIPIENTS=security-team@company.com
```

### Alert Thresholds
```python
{
    "max_requests_per_minute": 100,  # Maximum requests per minute per IP
    "suspicious_pattern_threshold": 0.8,  # Threshold for pattern detection
    "failed_attempts_threshold": 5  # Maximum failed attempts before alert
}
```

## Threat Detection

The monitor detects:
- Rate limit violations
- Suspicious input patterns
- Repeated failed attempts
- Unusual request patterns
- Potential adversarial attacks

## Logging

Logs are saved to: `security_{model_name}_{date}.log`

Log format:
```
timestamp - level - message
```

## Security Considerations

- Secure SMTP credentials
- Monitor alert thresholds
- Regular log review
- Update recipient list
- Rotate credentials

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT License - See [LICENSE](LICENSE)

