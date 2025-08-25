import os
import re
import requests
from linux.ssh_monitor import (
    get_vm_ssh_basic_analysis_by_ip,
    get_vm_ssh_security_analysis_by_ip,
)


class GeminiClient:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY")
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

    def _check_api_key(self):
        """Check if API key is available"""
        if not self.api_key:
            return "Gemini API key not configured. Please set GEMINI_API_KEY environment variable."
        return None

    def _call_gemini_api(self, prompt, temperature=0.2, max_tokens=1500):
        """Make API call to Gemini with improved error handling"""
        try:
            url = f"{self.base_url}?key={self.api_key}"

            headers = {"Content-Type": "application/json"}

            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": temperature,
                    "topK": 32,
                    "topP": 0.9,
                    "maxOutputTokens": max_tokens,
                    "candidateCount": 1,
                },
                "safetySettings": [
                    {
                        "category": "HARM_CATEGORY_HARASSMENT",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                    {
                        "category": "HARM_CATEGORY_HATE_SPEECH",
                        "threshold": "BLOCK_MEDIUM_AND_ABOVE",
                    },
                ],
            }

            print("Sending data to Gemini AI for analysis...")
            response = requests.post(url, headers=headers, json=payload, timeout=45)

            if response.status_code == 200:
                result = response.json()

                # Extract the generated text
                if "candidates" in result and len(result["candidates"]) > 0:
                    ai_response = result["candidates"][0]["content"]["parts"][0]["text"]
                    return ai_response
                else:
                    return "AI analysis failed: No response generated"
            else:
                return (
                    f"AI analysis failed: HTTP {response.status_code} - {response.text}"
                )

        except requests.exceptions.RequestException as e:
            return f"AI analysis failed: Network error - {str(e)}"
        except Exception as e:
            return f"AI analysis failed: {str(e)}"

    def _get_ubuntu_basic_prompt(self, ssh_data):
        """Generate optimized prompt for Ubuntu basic system analysis"""
        clean_ssh_data = re.sub(r"<.*?>", "", ssh_data)

        prompt = f"""
You are a Senior Linux Systems Engineer specializing in Ubuntu servers. Analyze this system monitoring data to help with incident response and performance troubleshooting.

The goal is to quickly identify issues that could be causing Zabbix alerts like high CPU, high memory usage, network problems, or service failures.

MONITORING DATA:
{clean_ssh_data}

Provide your analysis in this format:

## SYSTEM HEALTH OVERVIEW
- Overall Status: [HEALTHY/WARNING/CRITICAL]
- Primary Concerns: [List top 2-3 issues if any]

## PERFORMANCE ANALYSIS
### CPU & Memory & Load
- Current load vs CPU capacity
- Top CPU consuming processes and if they're normal
- Any load issues that need attention
- Memory usage patterns
- Potential memory leaks or high consumers
- Swap usage concerns

### Disk & Storage
- Disk space issues (>85% usage)
- I/O performance concerns
- Critical mount points status

### Network
- Interface status and connectivity
- Unusual connections or ports
- Network-related issues

## SERVICE STATUS
- Failed services that need attention

## IMMEDIATE ACTIONS NEEDED
[List specific actions if critical issues found, or "None" if system is healthy]

## INCIDENT TRIAGE PRIORITY
[HIGH/MEDIUM/LOW] - Based on severity of issues found

## ROOT CAUSE ANALYSIS
[Brief explanation of what might be causing any performance issues]

Focus on practical, actionable insights for system administrators responding to monitoring alerts.
"""
        return prompt

    def _get_ubuntu_security_prompt(self, ssh_data):
        """Generate optimized prompt for Ubuntu security analysis"""
        clean_ssh_data = re.sub(r"<.*?>", "", ssh_data)

        prompt = f"""
You are a Cybersecurity Analyst specializing in Linux server security. Analyze this Ubuntu system's security posture and identify potential threats or misconfigurations.

SECURITY DATA:
{clean_ssh_data}

Provide your analysis in this format:

## SECURITY THREAT ASSESSMENT
- Threat Level: [LOW/MEDIUM/HIGH/CRITICAL]
- Immediate Threats: [List any active threats found]

## AUTHENTICATION SECURITY
### Login Analysis
- Failed login patterns - brute force attempts?
- Successful login analysis - any suspicious access?
- User activity assessment

### Access Control
- Sudo usage patterns
- User privilege analysis
- Account security status

## PROCESS & NETWORK SECURITY
### Process Analysis
- Suspicious or unauthorized processes
- Root processes that shouldn't be running
- Resource-intensive processes from security perspective

### Network Security
- Unusual network connections or listening ports
- Firewall configuration assessment
- SSH configuration security

## INCIDENT RESPONSE RECOMMENDATIONS
### Immediate Actions
[List urgent security actions needed, or "None" if no immediate threats]

### Security Improvements
[List recommended security enhancements]

## SECURITY RISK LEVEL
[LOW/MEDIUM/HIGH/CRITICAL] - Overall security risk assessment

## THREAT INDICATORS
[List any specific indicators of compromise or security concerns found]

Focus on identifying actual security threats, not just theoretical vulnerabilities.
"""
        return prompt

    def analyze_ubuntu_basic_by_ip(self, ip_address, temperature=0.1):
        """Analyze Ubuntu system performance using direct IP address"""
        # Check API key
        api_error = self._check_api_key()
        if api_error:
            return f"❌ {api_error}"

        try:
            # Get basic monitoring data by IP
            print(f"📊 Gathering Ubuntu system data for IP: {ip_address}")
            ssh_data = get_vm_ssh_basic_analysis_by_ip(ip_address)

            # Check if SSH data collection failed
            if (
                ssh_data.startswith("SSH connection failed")
                or "not configured" in ssh_data
            ):
                return f"❌ {ssh_data}"

            # Generate prompt
            prompt = self._get_ubuntu_basic_prompt(ssh_data)

            # Get AI analysis
            ai_response = self._call_gemini_api(prompt, temperature, max_tokens=2000)

            if ai_response.startswith("AI analysis failed"):
                return f"❌ {ai_response}"

            return ai_response

        except Exception as e:
            return f"❌ Error analyzing Ubuntu basic data by IP: {str(e)}"

    def analyze_ubuntu_security_by_ip(self, ip_address, temperature=0.1):
        """Analyze Ubuntu system security using direct IP address"""
        # Check API key
        api_error = self._check_api_key()
        if api_error:
            return f"❌ {api_error}"

        try:
            # Get security monitoring data by IP
            print(f"🛡️ Gathering Ubuntu security data for IP: {ip_address}")
            ssh_data = get_vm_ssh_security_analysis_by_ip(ip_address)

            # Check if SSH data collection failed
            if (
                ssh_data.startswith("SSH connection failed")
                or "not configured" in ssh_data
            ):
                return f"❌ {ssh_data}"

            # Generate security prompt
            prompt = self._get_ubuntu_security_prompt(ssh_data)

            # Get AI analysis
            ai_response = self._call_gemini_api(prompt, temperature, max_tokens=2000)

            if ai_response.startswith("AI analysis failed"):
                return f"❌ {ai_response}"

            return ai_response

        except Exception as e:
            return f"❌ Error analyzing Ubuntu security data by IP: {str(e)}"

    def analyze_ssh_data(self, ip_address, temperature=0.2):
        """Legacy method - redirects to Ubuntu basic analysis"""
        return self.analyze_ubuntu_basic_by_ip(ip_address, temperature)

    def analyze_security_data(self, ip_address, temperature=0.2):
        """Legacy method - redirects to Ubuntu security analysis"""
        return self.analyze_ubuntu_security_by_ip(ip_address, temperature)
