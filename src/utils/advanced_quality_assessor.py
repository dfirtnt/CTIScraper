"""Advanced Quality Assessment System with Comprehensive Artifact Coverage.

This module provides a modern, multi-dimensional quality assessment system that covers
all major artifact types across Windows, Linux, macOS, cloud, and container environments.
"""

import json
import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class CriticalityLevel(Enum):
    """Criticality levels for artifacts."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class PlatformType(Enum):
    """Platform types for artifact analysis."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD = "cloud"
    CONTAINER = "container"


@dataclass
class ArtifactCategoryScore:
    """Score for a specific artifact category."""
    category: str
    coverage_score: int  # 0-100
    confidence: float  # 0.0-1.0
    artifacts_found: List[str]
    hunting_guidance: List[str]
    platform_specific: bool
    criticality: CriticalityLevel
    position: Tuple[int, int]  # (start, end) character positions


@dataclass
class AdvancedQualityAssessment:
    """Comprehensive quality assessment with modern artifact coverage."""
    
    # Core Quality Dimensions (0-100 each)
    artifact_coverage_score: int
    technical_depth_score: int
    actionable_intelligence_score: int
    threat_context_score: int
    detection_quality_score: int
    
    # Platform Coverage (0-100 each)
    windows_artifacts_score: int
    linux_artifacts_score: int
    macos_artifacts_score: int
    cloud_artifacts_score: int
    container_artifacts_score: int
    
    # Advanced Artifact Categories
    artifact_breakdown: Dict[str, ArtifactCategoryScore]
    
    # Threat Intelligence Quality
    threat_actor_coverage: List[str]
    malware_family_coverage: List[str]
    attack_vector_coverage: List[str]
    
    # Hunting Readiness
    hunting_priority: str  # Critical, High, Medium, Low
    hunting_confidence: float  # 0.0-1.0
    hunting_guidance: List[str]
    
    # Content Quality
    overall_quality_score: int  # 0-100
    quality_level: str  # "Critical", "High", "Medium", "Low"
    recommendations: List[str]


class AdvancedQualityAssessor:
    """Advanced quality assessment with comprehensive artifact coverage."""
    
    def __init__(self):
        """Initialize the advanced quality assessor."""
        self.artifact_categories = self._build_artifact_categories()
        self.platform_weights = {
            PlatformType.WINDOWS: 0.4,   # Most common in enterprise
            PlatformType.LINUX: 0.25,    # Growing in importance
            PlatformType.MACOS: 0.15,    # Increasing in enterprise
            PlatformType.CLOUD: 0.15,    # Critical for modern environments
            PlatformType.CONTAINER: 0.05 # Emerging but important
        }
        
        self.criticality_weights = {
            CriticalityLevel.CRITICAL: 1.0,
            CriticalityLevel.HIGH: 0.8,
            CriticalityLevel.MEDIUM: 0.6,
            CriticalityLevel.LOW: 0.4
        }
        
        self.quality_thresholds = {
            "Critical": 85,
            "High": 70,
            "Medium": 50,
            "Low": 0
        }
    
    def _build_artifact_categories(self) -> Dict[str, Dict]:
        """Build comprehensive artifact categories with patterns and guidance."""
        return {
            # Windows Artifacts
            "PROCESS": {
                "patterns": [
                    r'\b(process\s+injection|process\s+hollowing|process\s+creation)\b',
                    r'\b(createprocess|startprocess|process\s+spawning)\b',
                    r'\b(lsass|svchost|explorer|rundll32)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor process creation events",
                    "Look for unusual parent-child process relationships",
                    "Check for process injection indicators"
                ]
            },
            "CMDLINE": {
                "patterns": [
                    r'\b(powershell|cmd\.exe|command\s+line)\b',
                    r'\b(execution\s+policy|bypass|encoded\s+command)\b',
                    r'\b(iex|invoke-expression|start-process)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor command line execution",
                    "Look for encoded commands",
                    "Check for execution policy bypasses"
                ]
            },
            "REGISTRY": {
                "patterns": [
                    r'\b(registry\s+key|reg\s+add|startup\s+key)\b',
                    r'\b(hkey_local_machine|hkey_current_user)\b',
                    r'\b(run\s+key|runonce|image\s+file\s+execution)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor registry modifications",
                    "Check startup keys for persistence",
                    "Look for IFEO modifications"
                ]
            },
            "WMI": {
                "patterns": [
                    r'\b(wmi|windows\s+management\s+instrumentation)\b',
                    r'\b(wql\s+query|wmi\s+event|wmi\s+subscription)\b',
                    r'\b(wmiprvse|wmic|wmi\s+provider)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.CRITICAL,
                "guidance": [
                    "Monitor WMI event subscriptions",
                    "Check for WMI persistence mechanisms",
                    "Look for unusual WQL queries"
                ]
            },
            "SERVICES": {
                "patterns": [
                    r'\b(service\s+creation|service\s+modification)\b',
                    r'\b(service\s+hijacking|dll\s+hijacking)\b',
                    r'\b(sc\s+create|new-service|service\s+installation)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor service creation events",
                    "Check for service binary path tampering",
                    "Look for DLL hijacking indicators"
                ]
            },
            "SCHEDULED_TASKS": {
                "patterns": [
                    r'\b(scheduled\s+task|schtasks|at\s+command)\b',
                    r'\b(task\s+scheduler|task\s+creation)\b',
                    r'\b(trigger|action|persistence\s+mechanism)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor scheduled task creation",
                    "Check for suspicious task triggers",
                    "Look for persistence mechanisms"
                ]
            },
            "MEMORY": {
                "patterns": [
                    r'\b(memory\s+injection|shellcode|memory\s+dump)\b',
                    r'\b(process\s+memory|virtual\s+memory|heap\s+injection)\b',
                    r'\b(mimikatz|procdump|memory\s+analysis)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.CRITICAL,
                "guidance": [
                    "Monitor for memory injection indicators",
                    "Check for credential dumping activities",
                    "Look for shellcode patterns"
                ]
            },
            "CERTIFICATES": {
                "patterns": [
                    r'\b(code\s+signing|certificate|digital\s+signature)\b',
                    r'\b(self-signed|certificate\s+store|pki)\b',
                    r'\b(certmgr|certutil|certificate\s+installation)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.MEDIUM,
                "guidance": [
                    "Monitor certificate installations",
                    "Check for code signing abuse",
                    "Look for self-signed certificates"
                ]
            },
            
            # Linux/Unix Artifacts
            "CRON": {
                "patterns": [
                    r'\b(cron\s+job|crontab|scheduled\s+task)\b',
                    r'\b(at\s+command|batch\s+job|anacron)\b',
                    r'\b(/etc/crontab|/var/spool/cron)\b'
                ],
                "platform": PlatformType.LINUX,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor crontab modifications",
                    "Check for unusual cron jobs",
                    "Look for persistence mechanisms"
                ]
            },
            "BASH_HISTORY": {
                "patterns": [
                    r'\b(bash\s+history|\.bash_history|command\s+history)\b',
                    r'\b(history\s+manipulation|history\s+deletion)\b',
                    r'\b(histfile|histignore|history\s+size)\b'
                ],
                "platform": PlatformType.LINUX,
                "criticality": CriticalityLevel.MEDIUM,
                "guidance": [
                    "Monitor bash history modifications",
                    "Check for history manipulation",
                    "Look for command execution patterns"
                ]
            },
            "SUDO": {
                "patterns": [
                    r'\b(sudo\s+usage|privilege\s+escalation)\b',
                    r'\b(sudoers|visudo|sudo\s+bypass)\b',
                    r'\b(sudo\s+execution|elevated\s+privileges)\b'
                ],
                "platform": PlatformType.LINUX,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor sudo usage patterns",
                    "Check for privilege escalation",
                    "Look for sudo bypass techniques"
                ]
            },
            
            # Cloud/Modern Artifacts
            "POWERSHELL_REMOTING": {
                "patterns": [
                    r'\b(powershell\s+remoting|winrm|psremoting)\b',
                    r'\b(enter-pssession|invoke-command|new-pssession)\b',
                    r'\b(wsman|remote\s+execution|lateral\s+movement)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.CRITICAL,
                "guidance": [
                    "Monitor PowerShell remoting sessions",
                    "Check for lateral movement indicators",
                    "Look for remote execution patterns"
                ]
            },
            "CLOUD_API": {
                "patterns": [
                    r'\b(aws\s+api|azure\s+api|gcp\s+api)\b',
                    r'\b(cloud\s+credentials|access\s+key|secret\s+key)\b',
                    r'\b(ec2|s3|lambda|functions)\b'
                ],
                "platform": PlatformType.CLOUD,
                "criticality": CriticalityLevel.HIGH,
                "guidance": [
                    "Monitor cloud API calls",
                    "Check for credential exposure",
                    "Look for unauthorized resource access"
                ]
            },
            "CONTAINER": {
                "patterns": [
                    r'\b(docker|kubernetes|container\s+runtime)\b',
                    r'\b(pod|deployment|service|namespace)\b',
                    r'\b(container\s+escape|privileged\s+container)\b'
                ],
                "platform": PlatformType.CONTAINER,
                "criticality": CriticalityLevel.MEDIUM,
                "guidance": [
                    "Monitor container creation",
                    "Check for privileged containers",
                    "Look for container escape attempts"
                ]
            },
            
            # Advanced Persistence
            "COM_HIJACKING": {
                "patterns": [
                    r'\b(com\s+object|com\s+hijacking|com\s+registration)\b',
                    r'\b(ole|activex|com\s+server)\b',
                    r'\b(registry\s+com|clsid|progid)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.CRITICAL,
                "guidance": [
                    "Monitor COM object registrations",
                    "Check for COM hijacking",
                    "Look for suspicious COM servers"
                ]
            },
            "APPINIT_DLL": {
                "patterns": [
                    r'\b(appinit\s+dll|loadappinit_dlls|dll\s+injection)\b',
                    r'\b(registry\s+load|dll\s+loading|appinit)\b',
                    r'\b(load\s+library|dll\s+hijacking)\b'
                ],
                "platform": PlatformType.WINDOWS,
                "criticality": CriticalityLevel.CRITICAL,
                "guidance": [
                    "Monitor AppInit DLL registrations",
                    "Check for DLL hijacking",
                    "Look for suspicious DLL loading"
                ]
            }
        }
    
    def assess_content_quality(self, content: str, ttp_analysis: Optional[Dict] = None) -> AdvancedQualityAssessment:
        """Comprehensive quality assessment with advanced artifact coverage."""
        try:
            # 1. Artifact Coverage Analysis
            artifact_scores = self._analyze_artifact_coverage(content)
            
            # 2. Platform-Specific Analysis
            platform_scores = self._analyze_platform_coverage(content)
            
            # 3. Technical Depth Analysis
            technical_scores = self._analyze_technical_depth(content)
            
            # 4. Threat Context Analysis
            threat_scores = self._analyze_threat_context(content, ttp_analysis)
            
            # 5. Detection Quality Analysis
            detection_scores = self._analyze_detection_quality(content)
            
            # 6. Calculate Weighted Overall Score
            overall_score = self._calculate_weighted_score(
                artifact_scores, platform_scores, technical_scores,
                threat_scores, detection_scores
            )
            
            # 7. Generate Hunting Priority
            hunting_priority = self._determine_hunting_priority(overall_score, artifact_scores)
            
            return AdvancedQualityAssessment(
                artifact_coverage_score=artifact_scores["total"],
                technical_depth_score=technical_scores["total"],
                actionable_intelligence_score=detection_scores["total"],
                threat_context_score=threat_scores["total"],
                detection_quality_score=detection_scores["total"],
                windows_artifacts_score=platform_scores["windows"],
                linux_artifacts_score=platform_scores["linux"],
                macos_artifacts_score=platform_scores["macos"],
                cloud_artifacts_score=platform_scores["cloud"],
                container_artifacts_score=platform_scores["container"],
                artifact_breakdown=artifact_scores["breakdown"],
                threat_actor_coverage=threat_scores["actors"],
                malware_family_coverage=threat_scores["malware"],
                attack_vector_coverage=threat_scores["vectors"],
                hunting_priority=hunting_priority,
                hunting_confidence=overall_score["confidence"],
                hunting_guidance=self._generate_hunting_guidance(artifact_scores),
                overall_quality_score=overall_score["total"],
                quality_level=self._determine_quality_level(overall_score["total"]),
                recommendations=self._generate_recommendations(overall_score)
            )
            
        except Exception as e:
            logger.error(f"Advanced quality assessment failed: {e}")
            return self._create_default_assessment()
    
    def _analyze_artifact_coverage(self, content: str) -> Dict[str, Any]:
        """Analyze artifact coverage across all categories."""
        breakdown = {}
        total_score = 0
        total_artifacts = 0
        
        for category, config in self.artifact_categories.items():
            artifacts_found = []
            confidence = 0.0
            
            # Check each pattern in the category
            for pattern in config["patterns"]:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    artifacts_found.append(match.group())
                    confidence += 0.1  # Increment confidence for each match
            
            # Calculate category score
            if artifacts_found:
                coverage_score = min(len(artifacts_found) * 20, 100)
                confidence = min(confidence, 1.0)
                total_artifacts += len(artifacts_found)
            else:
                coverage_score = 0
                confidence = 0.0
            
            # Generate hunting guidance
            hunting_guidance = config["guidance"].copy()
            
            breakdown[category] = ArtifactCategoryScore(
                category=category,
                coverage_score=coverage_score,
                confidence=confidence,
                artifacts_found=artifacts_found,
                hunting_guidance=hunting_guidance,
                platform_specific=True,
                criticality=config["criticality"],
                position=(0, 0)  # Will be calculated if needed
            )
            
            # Weight by criticality
            weighted_score = coverage_score * self.criticality_weights[config["criticality"]]
            total_score += weighted_score
        
        # Normalize total score
        if total_artifacts > 0:
            total_score = min(total_score / len(self.artifact_categories), 100)
        else:
            total_score = 0
        
        return {
            "total": int(total_score),
            "breakdown": breakdown,
            "total_artifacts": total_artifacts
        }
    
    def _analyze_platform_coverage(self, content: str) -> Dict[str, int]:
        """Analyze platform-specific artifact coverage."""
        platform_scores = {
            "windows": 0,
            "linux": 0,
            "macos": 0,
            "cloud": 0,
            "container": 0
        }
        
        # Count artifacts by platform
        for category, config in self.artifact_categories.items():
            platform = config["platform"].value
            if platform in platform_scores:
                # Count matches for this category
                matches = 0
                for pattern in config["patterns"]:
                    matches += len(re.findall(pattern, content, re.IGNORECASE))
                
                if matches > 0:
                    platform_scores[platform] += matches * 10
        
        # Normalize scores
        for platform in platform_scores:
            platform_scores[platform] = min(platform_scores[platform], 100)
        
        return platform_scores
    
    def _analyze_technical_depth(self, content: str) -> Dict[str, int]:
        """Analyze technical depth and specificity."""
        score = 0
        breakdown = {}
        
        # Technical terminology (0-40 points)
        technical_terms = [
            'process injection', 'dll injection', 'registry modification',
            'lsass', 'mimikatz', 'pass the hash', 'living off the land',
            'process hollowing', 'code injection', 'memory injection',
            'wmi', 'powershell', 'cmd', 'rundll32', 'wscript',
            'scheduled task', 'service installation', 'startup key',
            'credential dumping', 'lateral movement', 'persistence',
            'privilege escalation', 'data exfiltration', 'command and control'
        ]
        
        term_count = sum(1 for term in technical_terms if term.lower() in content.lower())
        if term_count >= 8:
            term_score = 40
        elif term_count >= 5:
            term_score = 30
        elif term_count >= 3:
            term_score = 20
        elif term_count >= 1:
            term_score = 10
        else:
            term_score = 0
        
        score += term_score
        breakdown["technical_terminology"] = term_score
        
        # Practical details (0-30 points)
        practical_score = 0
        
        # Check for step-by-step procedures
        if re.search(r'\d+\.\s+\w+|step\s+\d+|first|then|next|finally', content, re.IGNORECASE):
            practical_score += 15
        
        # Check for configuration examples
        if re.search(r'config|setting|parameter|option|value\s*=|path\s*=', content, re.IGNORECASE):
            practical_score += 10
        
        # Check for tool usage
        if re.search(r'tool|software|application|utility|command|script', content, re.IGNORECASE):
            practical_score += 5
        
        score += practical_score
        breakdown["practical_details"] = practical_score
        
        # Advanced techniques (0-30 points)
        advanced_score = 0
        
        # Check for advanced persistence
        advanced_patterns = [
            'com hijacking', 'appinit dll', 'image file execution',
            'accessibility tool', 'registry run', 'scheduled task'
        ]
        
        advanced_count = sum(1 for pattern in advanced_patterns if pattern.lower() in content.lower())
        if advanced_count >= 3:
            advanced_score = 30
        elif advanced_count >= 2:
            advanced_score = 20
        elif advanced_count >= 1:
            advanced_score = 10
        
        score += advanced_score
        breakdown["advanced_techniques"] = advanced_score
        
        return {
            "total": min(score, 100),
            "breakdown": breakdown
        }
    
    def _analyze_threat_context(self, content: str, ttp_analysis: Optional[Dict] = None) -> Dict[str, Any]:
        """Analyze threat context and intelligence value."""
        score = 0
        breakdown = {}
        
        # Threat actor coverage (0-30 points)
        threat_actors = []
        actor_patterns = [
            r'\b(apt\d+|advanced\s+persistent\s+threat)\b',
            r'\b(cyber\s+group|hacking\s+group|threat\s+actor)\b',
            r'\b(attacker|adversary|malicious\s+actor)\b'
        ]
        
        for pattern in actor_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            threat_actors.extend(matches)
        
        if len(threat_actors) >= 3:
            actor_score = 30
        elif len(threat_actors) >= 1:
            actor_score = 20
        else:
            actor_score = 0
        
        score += actor_score
        breakdown["threat_actors"] = actor_score
        
        # Malware family coverage (0-30 points)
        malware_families = []
        malware_patterns = [
            r'\b(ransomware|trojan|backdoor|keylogger)\b',
            r'\b(malware|virus|worm|rootkit)\b',
            r'\b(rat|remote\s+access\s+trojan)\b'
        ]
        
        for pattern in malware_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            malware_families.extend(matches)
        
        if len(malware_families) >= 3:
            malware_score = 30
        elif len(malware_families) >= 1:
            malware_score = 20
        else:
            malware_score = 0
        
        score += malware_score
        breakdown["malware_families"] = malware_score
        
        # Attack vector coverage (0-40 points)
        attack_vectors = []
        vector_patterns = [
            r'\b(phishing|spear\s+phishing|social\s+engineering)\b',
            r'\b(exploit|vulnerability|cve-|zero-day)\b',
            r'\b(watering\s+hole|supply\s+chain|drive-by)\b'
        ]
        
        for pattern in vector_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            attack_vectors.extend(matches)
        
        if len(attack_vectors) >= 3:
            vector_score = 40
        elif len(attack_vectors) >= 1:
            vector_score = 25
        else:
            vector_score = 0
        
        score += vector_score
        breakdown["attack_vectors"] = vector_score
        
        return {
            "total": min(score, 100),
            "breakdown": breakdown,
            "actors": list(set(threat_actors)),
            "malware": list(set(malware_families)),
            "vectors": list(set(attack_vectors))
        }
    
    def _analyze_detection_quality(self, content: str) -> Dict[str, int]:
        """Analyze detection and hunting quality."""
        score = 0
        breakdown = {}
        
        # Detection methods (0-40 points)
        detection_score = 0
        
        # Check for detection rules
        if re.search(r'(sigma\s+rule|yara\s+rule|detection\s+rule)', content, re.IGNORECASE):
            detection_score += 20
        
        # Check for hunting queries
        if re.search(r'(splunk|elasticsearch|kql|spl|hunting\s+query)', content, re.IGNORECASE):
            detection_score += 20
        
        score += detection_score
        breakdown["detection_methods"] = detection_score
        
        # Actionable insights (0-30 points)
        actionable_score = 0
        
        # Check for defensive recommendations
        if re.search(r'recommend|mitigation|defense|protection|prevention', content, re.IGNORECASE):
            actionable_score += 15
        
        # Check for response procedures
        if re.search(r'response|incident|contain|eradicate|recover', content, re.IGNORECASE):
            actionable_score += 15
        
        score += actionable_score
        breakdown["actionable_insights"] = actionable_score
        
        # IOC coverage (0-30 points)
        ioc_score = 0
        
        # Check for indicators
        ioc_patterns = [
            r'\b(hash|sha256|md5|sha1)\b',
            r'\b(ip\s+address|domain|url|email)\b',
            r'\b(filename|registry\s+path|process\s+name)\b'
        ]
        
        ioc_count = sum(1 for pattern in ioc_patterns if re.search(pattern, content, re.IGNORECASE))
        if ioc_count >= 3:
            ioc_score = 30
        elif ioc_count >= 1:
            ioc_score = 15
        
        score += ioc_score
        breakdown["ioc_coverage"] = ioc_score
        
        return {
            "total": min(score, 100),
            "breakdown": breakdown
        }
    
    def _calculate_weighted_score(self, artifact_scores, platform_scores, technical_scores, threat_scores, detection_scores):
        """Calculate weighted overall score based on multiple factors."""
        
        weights = {
            "artifact_coverage": 0.35,    # Most important - actionable artifacts
            "technical_depth": 0.25,      # Technical accuracy
            "threat_context": 0.20,       # Threat intelligence value
            "detection_quality": 0.15,    # Detection and hunting guidance
            "platform_coverage": 0.05     # Platform diversity
        }
        
        # Calculate platform coverage total
        platform_total = sum(platform_scores.values()) / len(platform_scores)
        
        total_score = (
            artifact_scores["total"] * weights["artifact_coverage"] +
            technical_scores["total"] * weights["technical_depth"] +
            threat_scores["total"] * weights["threat_context"] +
            detection_scores["total"] * weights["detection_quality"] +
            platform_total * weights["platform_coverage"]
        )
        
        # Calculate confidence based on artifact coverage
        confidence = min(artifact_scores["total"] / 100.0, 1.0)
        
        return {
            "total": int(total_score),
            "confidence": confidence,
            "breakdown": {
                "artifact_coverage": artifact_scores["total"],
                "technical_depth": technical_scores["total"],
                "threat_context": threat_scores["total"],
                "detection_quality": detection_scores["total"],
                "platform_coverage": platform_total
            }
        }
    
    def _determine_hunting_priority(self, overall_score, artifact_scores):
        """Determine hunting priority based on comprehensive analysis."""
        
        # Critical factors
        critical_artifacts = sum(1 for cat in artifact_scores["breakdown"].values() 
                               if cat.criticality == CriticalityLevel.CRITICAL and cat.coverage_score > 0)
        high_artifacts = sum(1 for cat in artifact_scores["breakdown"].values() 
                           if cat.criticality == CriticalityLevel.HIGH and cat.coverage_score > 0)
        
        # Scoring logic
        priority_score = 0
        
        if critical_artifacts >= 2:
            priority_score += 40
        elif critical_artifacts >= 1:
            priority_score += 25
        
        if high_artifacts >= 3:
            priority_score += 30
        elif high_artifacts >= 1:
            priority_score += 15
        
        if overall_score["total"] >= 80:
            priority_score += 20
        elif overall_score["total"] >= 60:
            priority_score += 10
        
        # Determine priority level
        if priority_score >= 80:
            return "Critical"
        elif priority_score >= 60:
            return "High"
        elif priority_score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def _generate_hunting_guidance(self, artifact_scores):
        """Generate comprehensive hunting guidance based on artifacts found."""
        guidance = []
        
        # Collect guidance from all artifact categories
        for category, score in artifact_scores["breakdown"].items():
            if score.coverage_score > 0:
                guidance.extend(score.hunting_guidance)
        
        # Add general guidance based on coverage
        if artifact_scores["total"] >= 70:
            guidance.append("High artifact coverage - prioritize for immediate hunting")
        elif artifact_scores["total"] >= 40:
            guidance.append("Moderate artifact coverage - include in regular hunting rotation")
        else:
            guidance.append("Low artifact coverage - review for additional context")
        
        return list(set(guidance))  # Remove duplicates
    
    def _determine_quality_level(self, total_score: int) -> str:
        """Determine overall quality level based on total score."""
        if total_score >= self.quality_thresholds["Critical"]:
            return "Critical"
        elif total_score >= self.quality_thresholds["High"]:
            return "High"
        elif total_score >= self.quality_thresholds["Medium"]:
            return "Medium"
        else:
            return "Low"
    
    def _generate_recommendations(self, overall_score):
        """Generate actionable recommendations based on assessment."""
        recommendations = []
        
        breakdown = overall_score["breakdown"]
        
        if breakdown["artifact_coverage"] < 50:
            recommendations.append("Increase artifact coverage with more specific technical details")
        
        if breakdown["technical_depth"] < 50:
            recommendations.append("Add more technical depth with specific techniques and procedures")
        
        if breakdown["threat_context"] < 50:
            recommendations.append("Include more threat context with actor and malware information")
        
        if breakdown["detection_quality"] < 50:
            recommendations.append("Add detection methods and hunting queries")
        
        if breakdown["platform_coverage"] < 30:
            recommendations.append("Expand platform coverage beyond Windows")
        
        if not recommendations:
            recommendations.append("Content meets high quality standards for threat intelligence")
        
        return recommendations
    
    def _create_default_assessment(self) -> AdvancedQualityAssessment:
        """Create a default assessment when analysis fails."""
        return AdvancedQualityAssessment(
            artifact_coverage_score=0,
            technical_depth_score=0,
            actionable_intelligence_score=0,
            threat_context_score=0,
            detection_quality_score=0,
            windows_artifacts_score=0,
            linux_artifacts_score=0,
            macos_artifacts_score=0,
            cloud_artifacts_score=0,
            container_artifacts_score=0,
            artifact_breakdown={},
            threat_actor_coverage=[],
            malware_family_coverage=[],
            attack_vector_coverage=[],
            hunting_priority="Low",
            hunting_confidence=0.0,
            hunting_guidance=["Assessment failed - review content manually"],
            overall_quality_score=0,
            quality_level="Low",
            recommendations=["Quality assessment failed - review content manually"]
        )
    
    def generate_quality_report(self, assessment: AdvancedQualityAssessment) -> str:
        """Generate a detailed quality assessment report."""
        report = []
        report.append("🔍 Advanced Quality Assessment Report")
        report.append("=" * 60)
        report.append(f"Overall Quality: {assessment.quality_level}")
        report.append(f"Total Score: {assessment.overall_quality_score}/100")
        report.append(f"Hunting Priority: {assessment.hunting_priority}")
        report.append(f"Hunting Confidence: {assessment.hunting_confidence:.2f}")
        report.append("")
        
        report.append("📊 Quality Factor Breakdown:")
        report.append("-" * 40)
        report.append(f"Artifact Coverage: {assessment.artifact_coverage_score}/100")
        report.append(f"Technical Depth: {assessment.technical_depth_score}/100")
        report.append(f"Actionable Intelligence: {assessment.actionable_intelligence_score}/100")
        report.append(f"Threat Context: {assessment.threat_context_score}/100")
        report.append(f"Detection Quality: {assessment.detection_quality_score}/100")
        report.append("")
        
        report.append("🖥️ Platform Coverage:")
        report.append("-" * 20)
        report.append(f"Windows: {assessment.windows_artifacts_score}/100")
        report.append(f"Linux: {assessment.linux_artifacts_score}/100")
        report.append(f"macOS: {assessment.macos_artifacts_score}/100")
        report.append(f"Cloud: {assessment.cloud_artifacts_score}/100")
        report.append(f"Container: {assessment.container_artifacts_score}/100")
        report.append("")
        
        if assessment.threat_actor_coverage:
            report.append("🎭 Threat Actors:")
            report.append("-" * 15)
            for actor in assessment.threat_actor_coverage:
                report.append(f"• {actor}")
            report.append("")
        
        if assessment.malware_family_coverage:
            report.append("🦠 Malware Families:")
            report.append("-" * 18)
            for malware in assessment.malware_family_coverage:
                report.append(f"• {malware}")
            report.append("")
        
        if assessment.attack_vector_coverage:
            report.append("🎯 Attack Vectors:")
            report.append("-" * 16)
            for vector in assessment.attack_vector_coverage:
                report.append(f"• {vector}")
            report.append("")
        
        report.append("💡 Hunting Guidance:")
        report.append("-" * 18)
        for guidance in assessment.hunting_guidance:
            report.append(f"• {guidance}")
        report.append("")
        
        report.append("🔧 Recommendations:")
        report.append("-" * 15)
        for rec in assessment.recommendations:
            report.append(f"• {rec}")
        report.append("")
        
        report.append("✅ Assessment Complete!")
        
        return "\n".join(report)


# Convenience function for easy integration
def assess_content_quality_advanced(content: str, ttp_analysis: Optional[Dict] = None) -> AdvancedQualityAssessment:
    """
    Convenience function to assess content quality using advanced system.
    
    Args:
        content: Article content to assess
        ttp_analysis: Optional TTP analysis from existing detector
        
    Returns:
        AdvancedQualityAssessment with comprehensive quality scores
    """
    assessor = AdvancedQualityAssessor()
    return assessor.assess_content_quality(content, ttp_analysis)
