"""Threat Hunting Technique Detection and Analysis.

This module identifies specific, actionable techniques that security teams can hunt for
in their environments, focusing on detectable patterns rather than MITRE ATT&CK taxonomy.
"""

import re
import logging
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class HuntingTechnique:
    """Represents a huntable technique found in content."""
    technique_name: str
    category: str
    confidence: float
    context: str
    matched_text: str
    hunting_guidance: str
    position: Tuple[int, int]  # (start, end) character positions


@dataclass
class ThreatHuntingAnalysis:
    """Complete threat hunting analysis results for an article."""
    article_id: int
    total_techniques: int
    techniques_by_category: Dict[str, List[HuntingTechnique]]
    threat_actors: List[str]
    malware_families: List[str]
    attack_vectors: List[str]
    overall_confidence: float
    hunting_priority: str  # High, Medium, Low


class ThreatHuntingDetector:
    """
    Detects huntable techniques from threat intelligence content.
    
    Focuses on specific, actionable patterns that security teams can use
    for threat hunting in their environments.
    """
    
    def __init__(self):
        """Initialize the threat hunting detector."""
        self.technique_patterns = self._build_hunting_patterns()
        self.threat_actor_patterns = self._build_threat_actor_patterns()
        self.malware_patterns = self._build_malware_patterns()
        self.attack_vector_patterns = self._build_attack_vector_patterns()
    
    def _build_hunting_patterns(self) -> Dict[str, List[Dict]]:
        """Build patterns for huntable techniques organized by category."""
        return {
            "Credential Access": [
                {
                    "name": "Password Spraying",
                    "patterns": [
                        r'\b(Password\s+Spray|Password\s+Spraying|Credential\s+Spray)\b',
                        r'\b(Brute\s+Force.*Password|Password.*Brute\s+Force)\b',
                        r'\b(Mass\s+Login.*Attempt|Bulk\s+Authentication)\b',
                        # Broader patterns for limited content
                        r'\b(Password\s+Spray)\b',
                        r'\b(Credential\s+Spray)\b',
                        r'\b(Brute\s+Force)\b'
                    ],
                    "hunting_guidance": "Monitor for multiple failed login attempts across multiple accounts, look for authentication logs with high failure rates"
                },
                {
                    "name": "Credential Dumping",
                    "patterns": [
                        r'\b(Credential\s+Dump|Password\s+Dump|Hash\s+Dump)\b',
                        r'\b(Mimikatz|LSASS|Memory\s+Dump.*Credential)\b',
                        r'\b(Procdump.*LSASS|WDigest|Kerberos\s+Credential)\b',
                        # Broader patterns
                        r'\b(LSASS)\b',
                        r'\b(Credential\s+Dump)\b',
                        r'\b(Hash\s+Dump)\b'
                    ],
                    "hunting_guidance": "Look for LSASS memory dumps, unusual process creation, WDigest registry modifications, Kerberos ticket requests"
                },
                {
                    "name": "Keylogging",
                    "patterns": [
                        r'\b(Keylogger|Key\s+Logging|Keystroke\s+Capture)\b',
                        r'\b(Keyboard\s+Hook|Input\s+Capture|Keystroke\s+Monitoring)\b',
                        # Broader patterns
                        r'\b(Keylogger)\b',
                        r'\b(Keystroke\s+Capture)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual keyboard hook installations, look for processes with keyboard monitoring capabilities"
                }
            ],
            
            "Lateral Movement": [
                {
                    "name": "RDP Exploitation",
                    "patterns": [
                        r'\b(RDP.*Exploit|Remote\s+Desktop.*Attack)\b',
                        r'\b(RDP.*Brute\s+Force|RDP.*Password\s+Spray)\b',
                        r'\b(RDP.*Lateral|RDP.*Movement)\b',
                        # Broader patterns
                        r'\b(RDP)\b',
                        r'\b(Remote\s+Desktop)\b',
                        r'\b(Remote\s+Access)\b'
                    ],
                    "hunting_guidance": "Monitor RDP connection logs, look for unusual RDP connections from internal IPs, check for RDP brute force attempts"
                },
                {
                    "name": "SSH Hijacking",
                    "patterns": [
                        r'\b(SSH.*Hijack|SSH.*Compromise|SSH.*Lateral)\b',
                        r'\b(SSH.*Key\s+Exchange|SSH.*Authentication\s+Bypass)\b',
                        # Broader patterns
                        r'\b(SSH.*Hijack)\b',
                        r'\b(SSH.*Compromise)\b'
                    ],
                    "hunting_guidance": "Monitor SSH connection logs, look for unusual SSH key exchanges, check for SSH authentication bypass attempts"
                },
                {
                    "name": "Pass the Hash",
                    "patterns": [
                        r'\b(Pass\s+the\s+Hash|PtH|Hash\s+Passing)\b',
                        r'\b(NTLM.*Hash.*Reuse|Hash.*Authentication)\b',
                        # Broader patterns
                        r'\b(Pass\s+the\s+Hash)\b',
                        r'\b(PtH)\b'
                    ],
                    "hunting_guidance": "Monitor for NTLM authentication events, look for hash reuse across systems, check for unusual authentication patterns"
                }
            ],
            
            "Persistence": [
                {
                    "name": "Scheduled Task Creation",
                    "patterns": [
                        r'\b(Scheduled\s+Task.*Creation|Task\s+Scheduler.*Attack)\b',
                        r'\b(Cron\s+Job.*Malicious|Automated\s+Task.*Attack)\b',
                        r'\b(Windows\s+Task.*Persistence|Linux\s+Cron.*Persistence)\b',
                        # Broader patterns
                        r'\b(Scheduled\s+Task)\b',
                        r'\b(Cron\s+Job)\b',
                        r'\b(Task\s+Scheduler)\b'
                    ],
                    "hunting_guidance": "Monitor scheduled task creation, look for unusual task schedules, check for tasks running from suspicious locations"
                },
                {
                    "name": "Registry Modification",
                    "patterns": [
                        r'\b(Registry.*Run\s+Key|Startup.*Registry|Registry.*Persistence)\b',
                        r'\b(Run\s+Key.*Modification|Startup.*Key.*Attack)\b',
                        # Broader patterns
                        r'\b(Registry.*Run)\b',
                        r'\b(Startup.*Registry)\b'
                    ],
                    "hunting_guidance": "Monitor registry modifications to Run keys, look for unusual startup programs, check for registry changes in startup locations"
                },
                {
                    "name": "Service Installation",
                    "patterns": [
                        r'\b(Malicious\s+Service|Service.*Installation.*Attack)\b',
                        r'\b(Windows\s+Service.*Persistence|Service.*Persistence)\b',
                        # Broader patterns
                        r'\b(Malicious\s+Service)\b',
                        r'\b(Service.*Installation)\b',
                        r'\b(Service)\b'  # Very broad for limited content
                    ],
                    "hunting_guidance": "Monitor service creation events, look for unusual service names, check for services running from suspicious locations"
                }
            ],
            
            "Execution": [
                {
                    "name": "Process Injection",
                    "patterns": [
                        r'\b(Process\s+Injection|Code\s+Injection|DLL\s+Injection)\b',
                        r'\b(Process\s+Hollowing|Thread\s+Injection|Memory\s+Injection)\b',
                        # Broader patterns
                        r'\b(Process\s+Injection)\b',
                        r'\b(Code\s+Injection)\b',
                        r'\b(DLL\s+Injection)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual process creation, look for processes with unexpected parent processes, check for code injection events"
                },
                {
                    "name": "Living off the Land",
                    "patterns": [
                        r'\b(Living\s+off\s+the\s+Land|LotL|Built\s+in\s+Tools)\b',
                        r'\b(PowerShell.*Attack|WMI.*Attack|CMD.*Attack)\b',
                        r'\b(Legitimate\s+Tool.*Abuse|Built\s+in.*Malicious)\b',
                        # Broader patterns
                        r'\b(Living\s+off\s+the\s+Land)\b',
                        r'\b(LotL)\b',
                        r'\b(PowerShell.*Attack)\b',
                        r'\b(WMI.*Attack)\b'
                    ],
                    "hunting_guidance": "Monitor PowerShell execution, look for unusual WMI queries, check for command line tool usage patterns"
                },
                {
                    "name": "Fileless Execution",
                    "patterns": [
                        r'\b(Fileless\s+Attack|Memory\s+Based.*Execution)\b',
                        r'\b(No\s+File.*Execution|Memory.*Code.*Execution)\b',
                        # Broader patterns
                        r'\b(Fileless\s+Attack)\b',
                        r'\b(Memory\s+Based.*Execution)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual memory allocations, look for processes with unexpected memory regions, check for code execution without file creation"
                }
            ],
            
            "Defense Evasion": [
                {
                    "name": "Process Hiding",
                    "patterns": [
                        r'\b(Process\s+Hiding|Process\s+Obfuscation|Hidden\s+Process)\b',
                        r'\b(Process.*Disguise|Process.*Camouflage)\b',
                        # Broader patterns
                        r'\b(Process\s+Hiding)\b',
                        r'\b(Hidden\s+Process)\b'
                    ],
                    "hunting_guidance": "Look for processes with unusual names, check for processes that don't appear in task manager, monitor for process hiding techniques"
                },
                {
                    "name": "Anti-Detection",
                    "patterns": [
                        r'\b(Anti\s+Detection|Anti\s+Analysis|Detection\s+Evasion)\b',
                        r'\b(Sandbox\s+Evasion|VM\s+Detection|Analysis\s+Evasion)\b',
                        # Broader patterns
                        r'\b(Anti\s+Detection)\b',
                        r'\b(Detection\s+Evasion)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual system calls, look for environment detection attempts, check for anti-analysis behavior"
                },
                {
                    "name": "Security Tool Disabling",
                    "patterns": [
                        r'\b(Security\s+Tool.*Disable|AV.*Disable|Firewall.*Disable)\b',
                        r'\b(Endpoint.*Protection.*Bypass|Security.*Bypass)\b',
                        # Broader patterns
                        r'\b(Security\s+Tool.*Disable)\b',
                        r'\b(AV.*Disable)\b'
                    ],
                    "hunting_guidance": "Monitor for security service stops, look for unusual registry modifications to security tools, check for security tool tampering"
                }
            ],
            
            "Command & Control": [
                {
                    "name": "DNS Tunneling",
                    "patterns": [
                        r'\b(DNS\s+Tunneling|DNS.*Exfiltration|DNS.*C2)\b',
                        r'\b(DNS.*Command|DNS.*Control|DNS.*Communication)\b',
                        # Broader patterns
                        r'\b(DNS\s+Tunneling)\b',
                        r'\b(DNS.*C2)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual DNS queries, look for long DNS names, check for DNS traffic patterns that don't match normal web browsing"
                },
                {
                    "name": "HTTP C2",
                    "patterns": [
                        r'\b(HTTP.*C2|HTTP.*Command|HTTP.*Control)\b',
                        r'\b(Web.*Based.*C2|HTTP.*Communication.*Channel)\b',
                        # Broader patterns
                        r'\b(HTTP.*C2)\b',
                        r'\b(Web.*Based.*C2)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual HTTP requests, look for requests to suspicious domains, check for unusual HTTP headers or payloads"
                },
                {
                    "name": "Encrypted C2",
                    "patterns": [
                        r'\b(Encrypted.*C2|Encrypted.*Communication|TLS.*C2)\b',
                        r'\b(SSL.*Tunnel|Encrypted.*Tunnel.*C2)\b',
                        # Broader patterns
                        r'\b(Encrypted.*C2)\b',
                        r'\b(TLS.*C2)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual TLS connections, look for connections to suspicious IPs, check for unusual certificate usage"
                }
            ],
            
            "Data Exfiltration": [
                {
                    "name": "Data Staging",
                    "patterns": [
                        r'\b(Data\s+Staging|Data.*Collection.*Point|Staging.*Area)\b',
                        r'\b(Data.*Gathering.*Point|Collection.*Point)\b',
                        # Broader patterns
                        r'\b(Data\s+Staging)\b',
                        r'\b(Staging.*Area)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual file creation in staging directories, look for large data transfers, check for unusual data collection patterns"
                },
                {
                    "name": "Exfiltration Over Network",
                    "patterns": [
                        r'\b(Data.*Exfiltration.*Network|Network.*Data.*Theft)\b',
                        r'\b(Data.*Upload.*External|External.*Data.*Transfer)\b',
                        # Broader patterns
                        r'\b(Data.*Exfiltration)\b',
                        r'\b(Network.*Data.*Theft)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual outbound connections, look for large data transfers, check for connections to suspicious external destinations"
                },
                {
                    "name": "Exfiltration Over Physical Media",
                    "patterns": [
                        r'\b(USB.*Exfiltration|Physical.*Media.*Theft)\b',
                        r'\b(Removable.*Media.*Data|USB.*Data.*Theft)\b',
                        # Broader patterns
                        r'\b(USB.*Exfiltration)\b',
                        r'\b(Physical.*Media.*Theft)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual USB device usage, look for large data transfers to removable media, check for unusual file access patterns"
                }
            ],
            
            # Add new category for broader threat indicators
            "Threat Indicators": [
                {
                    "name": "Malware Detection",
                    "patterns": [
                        r'\b(Malware|Ransomware|Trojan|RAT|Backdoor|Worm|Virus)\b',
                        r'\b(Spyware|Adware|Loader|Dropper|Packer)\b',
                        # Very broad patterns for limited content
                        r'\b(Malware)\b',
                        r'\b(Ransomware)\b',
                        r'\b(Trojan)\b',
                        r'\b(RAT)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual file creation, look for suspicious process behavior, check for unusual network connections"
                },
                {
                    "name": "Intrusion Indicators",
                    "patterns": [
                        r'\b(Intrusion|Breach|Compromise|Attack|Exploit)\b',
                        r'\b(Threat|Actor|Campaign|Operation)\b',
                        # Very broad patterns
                        r'\b(Intrusion)\b',
                        r'\b(Breach)\b',
                        r'\b(Compromise)\b',
                        r'\b(Attack)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual system activity, look for unauthorized access attempts, check for unusual user behavior"
                }
            ],
            
            # NEW: High-Value Hunting Patterns (Based on user's analysis)
            "High-Value Hunting Patterns": [
                {
                    "name": "Process Chain Detection",
                    "patterns": [
                        r'\b(ParentImage|Parent.*Process|Process.*Chain)\b',
                        r'\b(PowerShell.*spawn|Process.*spawning|Child.*process)\b',
                        r'\b(\\\\.*\.exe.*\\\\.*\.exe|Process.*hierarchy)\b',
                        # Specific process chains
                        r'\b(powershell\.exe.*php\.exe)\b',
                        r'\b(cmd\.exe.*powershell\.exe)\b',
                        r'\b(wscript\.exe.*rundll32\.exe)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual parent-child process relationships, look for PowerShell spawning unexpected processes, check for process chains that don't match normal application behavior"
                },
                {
                    "name": "Registry Persistence",
                    "patterns": [
                        r'\b(Registry.*Run|Run.*Key|Startup.*Registry)\b',
                        r'\b(\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)\b',
                        r'\b(Registry.*modification|Registry.*key)\b',
                        # Specific registry patterns
                        r'\b(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)\b',
                        r'\b(HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)\b'
                    ],
                    "hunting_guidance": "Monitor registry modifications to Run keys, look for unusual startup programs, check for registry changes in startup locations, focus on HKCU and HKLM Run keys"
                },
                {
                    "name": "Command Pattern Detection",
                    "patterns": [
                        r'\b(systeminfo|tasklist|Get-Service|Get-Process)\b',
                        r'\b(Get-NetNeighbor|Get-NetRoute|netstat)\b',
                        r'\b(CommandLine|Command.*Line|Command.*arguments)\b',
                        # Specific reconnaissance commands
                        r'\b(Get-WmiObject|wmic|Get-ComputerInfo)\b',
                        r'\b(Get-ADUser|Get-ADComputer|Get-ADGroup)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual command execution patterns, look for reconnaissance commands in unexpected contexts, check for PowerShell commands that gather system information"
                },
                {
                    "name": "File Path Specificity",
                    "patterns": [
                        r'\b(\\AppData\\Roaming\\|\\AppData\\Local\\|\\Temp\\)\b',
                        r'\b(\\Users\\\w+\\AppData\\|\\ProgramData\\)\b',
                        r'\b(Suspicious.*path|Unusual.*location|Malicious.*directory)\b',
                        # Specific suspicious paths
                        r'\b(\\AppData\\Roaming\\php\\php\.exe)\b',
                        r'\b(\\AppData\\Local\\Temp\\\w+\.exe)\b'
                    ],
                    "hunting_guidance": "Monitor for unusual file creation in suspicious locations, look for executables in AppData directories, check for unusual file paths that don't match normal application behavior"
                },
                {
                    "name": "Network Infrastructure",
                    "patterns": [
                        r'\b(trycloudflare\.com|cloudflare\.com)\b',
                        r'\b(Suspicious.*domain|Malicious.*IP|C2.*infrastructure)\b',
                        r'\b(Command.*and.*Control|C2|C&C)\b',
                        # Specific network patterns
                        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',  # IP addresses
                        r'\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b'  # Domain patterns
                    ],
                    "hunting_guidance": "Monitor for connections to suspicious domains and IPs, look for abuse of legitimate services like Cloudflare, check for unusual network traffic patterns"
                },
                {
                    "name": "Sigma Rule Content",
                    "patterns": [
                        r'\b(Sigma.*rule|Detection.*rule|Hunting.*rule)\b',
                        r'\b(selection:|detection:|condition:)\b',
                        r'\b(MITRE.*ATT&CK|T\d{4}\.\d{3})\b',
                        # Specific Sigma syntax
                        r'\b(ParentImage|Image|CommandLine|TargetObject)\b',
                        r'\b(endswith|contains|matches_regex)\b'
                    ],
                    "hunting_guidance": "This content contains Sigma detection rules - extract and implement these rules in your SIEM, look for MITRE ATT&CK technique mappings, focus on the specific detection logic provided"
                }
            ]
        }
    
    def _build_threat_actor_patterns(self) -> List[str]:
        """Build patterns for threat actor identification."""
        return [
            r'\b(APT|Advanced\s+Persistent\s+Threat)\s+(\d+|[A-Z]+)\b',
            r'\b(APT|Group)\s+([A-Z0-9]+)\b',
            r'\b([A-Z][a-z]+)\s+(Group|Team|Gang)\b',
            r'\b([A-Z][a-z]+)\s+(APT|Advanced\s+Persistent\s+Threat)\b',
            r'\b(State\s+Sponsored|Nation\s+State|Government\s+Backed)\b',
            r'\b(Cybercrime\s+Group|Hacktivist\s+Group|Cyber\s+Criminal)\b'
        ]
    
    def _build_malware_patterns(self) -> List[str]:
        """Build patterns for malware family identification."""
        return [
            r'\b([A-Z][a-z]+)\s+(RAT|Trojan|Backdoor|Worm|Virus)\b',
            r'\b([A-Z][a-z]+)\s+(Malware|Spyware|Adware)\b',
            r'\b([A-Z][a-z]+)\s+(Loader|Dropper|Packer)\b',
            r'\b([A-Z][a-z]+)\s+(Ransomware|Crypto\s+Locker)\b',
            r'\b([A-Z][a-z]+)\s+(Keylogger|Stealer|Spyware)\b'
        ]
    
    def _build_attack_vector_patterns(self) -> List[str]:
        """Build patterns for attack vector identification."""
        return [
            r'\b(Phishing|Spear\s+Phishing|Whaling)\b',
            r'\b(Social\s+Engineering|Social\s+Manipulation)\b',
            r'\b(Supply\s+Chain|Third\s+Party)\s+(Attack|Compromise)\b',
            r'\b(Watering\s+Hole|Drive\s+By)\s+(Attack|Compromise)\b',
            r'\b(Privilege\s+Escalation|Lateral\s+Movement)\b',
            r'\b(Persistence|Persistence\s+Mechanism)\b',
            r'\b(Command\s+and\s+Control|C2|C&C)\b',
            r'\b(Data\s+Exfiltration|Data\s+Theft)\b'
        ]
    
    def detect_hunting_techniques(self, content: str, article_id: int) -> ThreatHuntingAnalysis:
        """
        Detect huntable techniques from threat intelligence content.
        
        Args:
            content: The article content to analyze
            article_id: ID of the article being analyzed
            
        Returns:
            ThreatHuntingAnalysis object with all detected techniques and hunting guidance
        """
        techniques_by_category = defaultdict(list)
        threat_actors = self._extract_threat_actors(content)
        malware_families = self._extract_malware_families(content)
        attack_vectors = self._extract_attack_vectors(content)
        
        # Detect techniques in each category
        for category, techniques in self.technique_patterns.items():
            for technique in techniques:
                for pattern in technique["patterns"]:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        hunting_technique = HuntingTechnique(
                            technique_name=technique["name"],
                            category=category,
                            confidence=self._calculate_technique_confidence(match, content, technique),
                            context=self._extract_context(content, match.start(), match.end()),
                            matched_text=match.group(),
                            hunting_guidance=technique["hunting_guidance"],
                            position=(match.start(), match.end())
                        )
                        techniques_by_category[category].append(hunting_technique)
        
        # Calculate overall confidence and hunting priority
        overall_confidence = self._calculate_overall_confidence(techniques_by_category, content)
        hunting_priority = self._determine_hunting_priority(techniques_by_category, overall_confidence)
        
        return ThreatHuntingAnalysis(
            article_id=article_id,
            total_techniques=sum(len(techs) for techs in techniques_by_category.values()),
            techniques_by_category=dict(techniques_by_category),
            threat_actors=threat_actors,
            malware_families=malware_families,
            attack_vectors=attack_vectors,
            overall_confidence=overall_confidence,
            hunting_priority=hunting_priority
        )
    
    def _calculate_technique_confidence(self, match: re.Match, content: str, technique: Dict) -> float:
        """Calculate confidence score for a hunting technique."""
        confidence = 0.5  # Base confidence
        
        # Higher confidence for exact matches
        if match.group().isupper():
            confidence += 0.2
        
        # Higher confidence for technical context
        context = self._extract_context(content, match.start(), match.end())
        technical_terms = ['attack', 'threat', 'malware', 'exploit', 'vulnerability', 'compromise']
        if any(term in context.lower() for term in technical_terms):
            confidence += 0.2
        
        # Higher confidence for recent/current threat context
        time_terms = ['2024', '2025', 'recent', 'current', 'ongoing', 'active']
        if any(term in context.lower() for term in time_terms):
            confidence += 0.1
        
        return min(confidence, 1.0)
    
    def _calculate_overall_confidence(self, techniques_by_category: Dict, content: str) -> float:
        """Calculate overall confidence score for the analysis."""
        if not techniques_by_category:
            return 0.0
        
        # Get all techniques
        all_techniques = [tech for techs in techniques_by_category.values() for tech in techs]
        
        # Average confidence of individual techniques
        avg_confidence = sum(tech.confidence for tech in all_techniques) / len(all_techniques)
        
        # Bonus for multiple techniques
        technique_bonus = min(len(all_techniques) * 0.05, 0.2)
        
        # Bonus for content length (more content = more potential for analysis)
        length_bonus = min(len(content) / 10000 * 0.1, 0.1)
        
        return min(avg_confidence + technique_bonus + length_bonus, 1.0)
    
    def _determine_hunting_priority(self, techniques_by_category: Dict, confidence: float) -> str:
        """Determine hunting priority based on techniques and confidence."""
        if not techniques_by_category:
            return "Low"
        
        # Count high-value techniques
        high_value_categories = ["Credential Access", "Lateral Movement", "Persistence", "Command & Control", "High-Value Hunting Patterns"]
        high_value_count = sum(len(techniques_by_category.get(cat, [])) for cat in high_value_categories)
        
        if high_value_count >= 3 or confidence >= 0.8:
            return "High"
        elif high_value_count >= 1 or confidence >= 0.6:
            return "Medium"
        else:
            return "Low"
    
    def calculate_ttp_quality_score(self, content: str) -> Dict[str, Any]:
        """
        Calculate TTP quality score based on the user's analysis framework.
        
        Returns a quality assessment with scoring and recommendations.
        """
        content_lower = content.lower()
        quality_factors = {}
        
        # 1. Sigma Rules Present (15 points)
        sigma_indicators = [
            'sigma rule', 'detection rule', 'hunting rule',
            'selection:', 'detection:', 'condition:',
            'parentimage', 'image', 'commandline', 'targetobject',
            'endswith', 'contains', 'matches_regex'
        ]
        sigma_score = sum(15 if indicator in content_lower else 0 for indicator in sigma_indicators)
        quality_factors['sigma_rules_present'] = min(sigma_score, 15)
        
        # 2. MITRE ATT&CK Mapping (10 points)
        mitre_patterns = [
            r'T\d{4}',  # Basic technique ID
            r'T\d{4}\.\d{3}',  # Sub-technique ID
            r'mitre.*att&ck', r'att&ck.*framework'
        ]
        mitre_score = 0
        for pattern in mitre_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                mitre_score += 5
        quality_factors['mitre_attack_mapping'] = min(mitre_score, 10)
        
        # 3. Process Chains (12 points)
        process_chain_indicators = [
            'parentimage', 'parent process', 'process chain',
            'powershell spawn', 'process spawning', 'child process',
            'process hierarchy', 'parent-child'
        ]
        process_chain_score = sum(3 if indicator in content_lower else 0 for indicator in process_chain_indicators)
        quality_factors['process_chains'] = min(process_chain_score, 12)
        
        # 4. Registry Operations (8 points)
        registry_indicators = [
            'registry run', 'run key', 'startup registry',
            'hkey_current_user', 'hkey_local_machine',
            'software\\microsoft\\windows\\currentversion\\run'
        ]
        registry_score = sum(2 if indicator in content_lower else 0 for indicator in registry_indicators)
        quality_factors['registry_operations'] = min(registry_score, 8)
        
        # 5. Network IOCs (7 points)
        network_indicators = [
            'trycloudflare.com', 'cloudflare.com',
            'suspicious domain', 'malicious ip', 'c2 infrastructure',
            'command and control', 'c2', 'c&c'
        ]
        # Count IP addresses and domains
        ip_count = len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content))
        domain_count = len(re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', content))
        network_score = sum(2 if indicator in content_lower else 0 for indicator in network_indicators)
        network_score += min(ip_count, 2) + min(domain_count, 2)
        quality_factors['network_iocs'] = min(network_score, 7)
        
        # 6. File Path Specificity (9 points)
        file_path_indicators = [
            '\\appdata\\roaming\\', '\\appdata\\local\\', '\\temp\\',
            '\\users\\', '\\programdata\\', 'suspicious path',
            'unusual location', 'malicious directory'
        ]
        file_path_score = sum(2 if indicator in content_lower else 0 for indicator in file_path_indicators)
        quality_factors['file_path_specificity'] = min(file_path_score, 9)
        
        # 7. Command Patterns (8 points)
        command_indicators = [
            'systeminfo', 'tasklist', 'get-service', 'get-process',
            'get-netneighbor', 'get-netroute', 'netstat',
            'commandline', 'command line', 'command arguments',
            'get-wmiobject', 'wmic', 'get-computerinfo'
        ]
        command_score = sum(1 if indicator in content_lower else 0 for indicator in command_indicators)
        quality_factors['command_patterns'] = min(command_score, 8)
        
        # 8. Campaign Attribution (6 points)
        campaign_indicators = [
            'campaign', 'threat actor', 'apt', 'group',
            'variant', 'family', 'malware family'
        ]
        campaign_score = sum(2 if indicator in content_lower else 0 for indicator in campaign_indicators)
        quality_factors['campaign_attribution'] = min(campaign_score, 6)
        
        # Calculate total score
        total_score = sum(quality_factors.values())
        quality_factors['total_score'] = total_score
        quality_factors['max_possible'] = 75
        
        # Determine quality level
        if total_score >= 60:
            quality_level = "Excellent"
            recommendation = "This content contains high-value hunting intelligence. Extract all patterns and implement detection rules immediately."
        elif total_score >= 45:
            quality_level = "Good"
            recommendation = "This content has solid hunting value. Focus on the high-scoring areas and implement relevant detection rules."
        elif total_score >= 30:
            quality_level = "Fair"
            recommendation = "This content has some hunting value but needs additional context. Use as supplementary intelligence."
        else:
            quality_level = "Limited"
            recommendation = "This content has minimal hunting value. Consider for general awareness only."
        
        quality_factors['quality_level'] = quality_level
        quality_factors['recommendation'] = recommendation
        
        return quality_factors
    
    def generate_quality_report(self, content: str) -> str:
        """Generate a detailed TTP quality assessment report."""
        quality_data = self.calculate_ttp_quality_score(content)
        
        report = []
        report.append("🔍 TTP Quality Assessment Report")
        report.append("=" * 60)
        report.append(f"Overall Quality: {quality_data['quality_level']}")
        report.append(f"Total Score: {quality_data['total_score']}/{quality_data['max_possible']}")
        report.append("")
        
        report.append("📊 Quality Factor Breakdown:")
        report.append("-" * 40)
        
        # Sort factors by score (highest first)
        sorted_factors = sorted(
            [(k, v) for k, v in quality_data.items() if k not in ['total_score', 'max_possible', 'quality_level', 'recommendation']],
            key=lambda x: x[1],
            reverse=True
        )
        
        for factor, score in sorted_factors:
            factor_name = factor.replace('_', ' ').title()
            report.append(f"{factor_name}: {score}")
        
        report.append("")
        report.append("💡 Recommendation:")
        report.append("-" * 20)
        report.append(quality_data['recommendation'])
        
        report.append("")
        report.append("🎯 High-Value Areas to Focus On:")
        report.append("-" * 40)
        
        # Identify top 3 scoring areas
        top_areas = sorted_factors[:3]
        for factor, score in top_areas:
            if score > 0:
                factor_name = factor.replace('_', ' ').title()
                report.append(f"• {factor_name} (Score: {score})")
        
        report.append("")
        report.append("✅ Assessment Complete!")
        
        return "\n".join(report)
    
    def _extract_threat_actors(self, content: str) -> List[str]:
        """Extract threat actor mentions from content."""
        actors = []
        for pattern in self.threat_actor_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                actors.append(match.group())
        return list(set(actors))
    
    def _extract_malware_families(self, content: str) -> List[str]:
        """Extract malware family mentions from content."""
        families = []
        for pattern in self.malware_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                families.append(match.group())
        return list(set(families))
    
    def _extract_attack_vectors(self, content: str) -> List[str]:
        """Extract attack vector mentions from content."""
        vectors = []
        for pattern in self.attack_vector_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                vectors.append(match.group())
        return list(set(vectors))
    
    def _extract_context(self, content: str, start: int, end: int) -> str:
        """Extract context around a technique match."""
        context_size = 100
        start_context = max(0, start - context_size)
        end_context = min(len(content), end + context_size)
        
        context = content[start_context:end_context]
        if start_context > 0:
            context = "..." + context
        if end_context < len(content):
            context = context + "..."
        
        return context.strip()
    
    def generate_hunting_report(self, analysis: ThreatHuntingAnalysis) -> str:
        """Generate a human-readable hunting report."""
        report = []
        report.append(f"Threat Hunting Analysis Report for Article {analysis.article_id}")
        report.append("=" * 60)
        report.append(f"Total Techniques: {analysis.total_techniques}")
        report.append(f"Overall Confidence: {analysis.overall_confidence:.2f}")
        report.append(f"Hunting Priority: {analysis.hunting_priority}")
        report.append("")
        
        if analysis.techniques_by_category:
            report.append("🎯 HUNTABLE TECHNIQUES BY CATEGORY:")
            report.append("=" * 50)
            for category, techniques in analysis.techniques_by_category.items():
                report.append(f"\n📋 {category.upper()}:")
                for i, tech in enumerate(techniques, 1):
                    report.append(f"  {i}. {tech.technique_name}")
                    report.append(f"     Confidence: {tech.confidence:.2f}")
                    report.append(f"     Matched: \"{tech.matched_text}\"")
                    report.append(f"     🎯 Hunting: {tech.hunting_guidance}")
                    report.append("")
        
        if analysis.threat_actors:
            report.append("👥 THREAT ACTORS MENTIONED:")
            report.append("=" * 30)
            for actor in analysis.threat_actors:
                report.append(f"  • {actor}")
            report.append("")
        
        if analysis.malware_families:
            report.append("🦠 MALWARE FAMILIES MENTIONED:")
            report.append("=" * 30)
            for malware in analysis.malware_families:
                report.append(f"  • {malware}")
            report.append("")
        
        if analysis.attack_vectors:
            report.append("⚔️ ATTACK VECTORS IDENTIFIED:")
            report.append("=" * 30)
            for vector in analysis.attack_vectors:
                report.append(f"  • {vector}")
            report.append("")
        
        report.append("✅ Analysis Complete!")
        return "\n".join(report)
