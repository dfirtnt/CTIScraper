"""Integrated Quality Assessment System.

This module provides a unified interface for comprehensive quality assessment
and TTP extraction, combining the advanced quality assessor and enhanced TTP extractor.
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass

from .advanced_quality_assessor import (
    AdvancedQualityAssessment, 
    AdvancedQualityAssessor,
    assess_content_quality_advanced
)
from .enhanced_ttp_extractor import (
    EnhancedThreatHuntingAnalysis,
    EnhancedThreatHuntingDetector,
    extract_enhanced_techniques
)

logger = logging.getLogger(__name__)


@dataclass
class IntegratedQualityResult:
    """Comprehensive quality assessment result combining all analyses."""
    
    # Article metadata
    article_id: int
    article_title: str
    source_url: str
    
    # Quality assessment results
    quality_assessment: AdvancedQualityAssessment
    
    # TTP extraction results
    ttp_analysis: EnhancedThreatHuntingAnalysis
    
    # Combined metrics
    overall_score: int  # 0-100
    overall_quality_level: str  # Critical, High, Medium, Low
    hunting_priority: str  # Critical, High, Medium, Low
    confidence_score: float  # 0.0-1.0
    
    # Summary statistics
    total_artifacts_found: int
    total_techniques_found: int
    platforms_covered: List[str]
    critical_artifacts: int
    high_artifacts: int
    
    # Recommendations
    recommendations: List[str]
    hunting_guidance: List[str]
    next_steps: List[str]


class IntegratedQualitySystem:
    """Integrated quality assessment system combining advanced analysis capabilities."""
    
    def __init__(self):
        """Initialize the integrated quality system."""
        self.quality_assessor = AdvancedQualityAssessor()
        self.ttp_detector = EnhancedThreatHuntingDetector()
        
        # Integration weights
        self.integration_weights = {
            "quality_assessment": 0.4,
            "ttp_analysis": 0.6
        }
    
    def analyze_content(self, 
                       content: str, 
                       article_id: int = 0,
                       article_title: str = "",
                       source_url: str = "") -> IntegratedQualityResult:
        """
        Perform comprehensive content analysis.
        
        Args:
            content: Article content to analyze
            article_id: Article identifier
            article_title: Article title
            source_url: Source URL
            
        Returns:
            IntegratedQualityResult with comprehensive analysis
        """
        try:
            # 1. Perform advanced quality assessment
            quality_assessment = self.quality_assessor.assess_content_quality(content)
            
            # 2. Perform enhanced TTP extraction
            ttp_analysis = self.ttp_detector.extract_enhanced_techniques(content)
            
            # 3. Integrate results
            integrated_result = self._integrate_results(
                quality_assessment, ttp_analysis, article_id, article_title, source_url
            )
            
            return integrated_result
            
        except Exception as e:
            logger.error(f"Integrated analysis failed: {e}")
            return self._create_default_result(article_id, article_title, source_url)
    
    def _integrate_results(self, 
                          quality_assessment: AdvancedQualityAssessment,
                          ttp_analysis: EnhancedThreatHuntingAnalysis,
                          article_id: int,
                          article_title: str,
                          source_url: str) -> IntegratedQualityResult:
        """Integrate quality assessment and TTP analysis results."""
        
        # Calculate combined metrics
        overall_score = self._calculate_overall_score(quality_assessment, ttp_analysis)
        overall_quality_level = self._determine_overall_quality_level(overall_score)
        hunting_priority = self._determine_hunting_priority(quality_assessment, ttp_analysis)
        confidence_score = self._calculate_confidence_score(quality_assessment, ttp_analysis)
        
        # Calculate summary statistics
        total_artifacts = self._count_total_artifacts(quality_assessment)
        total_techniques = ttp_analysis.total_techniques
        platforms_covered = self._get_platforms_covered(quality_assessment, ttp_analysis)
        critical_artifacts = self._count_critical_artifacts(quality_assessment, ttp_analysis)
        high_artifacts = self._count_high_artifacts(quality_assessment, ttp_analysis)
        
        # Generate recommendations
        recommendations = self._generate_integrated_recommendations(quality_assessment, ttp_analysis)
        hunting_guidance = self._generate_integrated_hunting_guidance(quality_assessment, ttp_analysis)
        next_steps = self._generate_next_steps(overall_score, hunting_priority, critical_artifacts)
        
        return IntegratedQualityResult(
            article_id=article_id,
            article_title=article_title,
            source_url=source_url,
            quality_assessment=quality_assessment,
            ttp_analysis=ttp_analysis,
            overall_score=overall_score,
            overall_quality_level=overall_quality_level,
            hunting_priority=hunting_priority,
            confidence_score=confidence_score,
            total_artifacts_found=total_artifacts,
            total_techniques_found=total_techniques,
            platforms_covered=platforms_covered,
            critical_artifacts=critical_artifacts,
            high_artifacts=high_artifacts,
            recommendations=recommendations,
            hunting_guidance=hunting_guidance,
            next_steps=next_steps
        )
    
    def _calculate_overall_score(self, 
                                quality_assessment: AdvancedQualityAssessment,
                                ttp_analysis: EnhancedThreatHuntingAnalysis) -> int:
        """Calculate overall score combining quality and TTP analysis."""
        
        # Quality assessment contributes 40%
        quality_score = quality_assessment.overall_quality_score * self.integration_weights["quality_assessment"]
        
        # TTP analysis contributes 60%
        ttp_score = ttp_analysis.content_quality_score * self.integration_weights["ttp_analysis"]
        
        # Bonus for critical artifacts
        critical_bonus = 0
        if ttp_analysis.hunting_priority == "Critical":
            critical_bonus = 10
        elif ttp_analysis.hunting_priority == "High":
            critical_bonus = 5
        
        total_score = quality_score + ttp_score + critical_bonus
        return min(int(total_score), 100)
    
    def _determine_overall_quality_level(self, overall_score: int) -> str:
        """Determine overall quality level based on integrated score."""
        if overall_score >= 85:
            return "Critical"
        elif overall_score >= 70:
            return "High"
        elif overall_score >= 50:
            return "Medium"
        else:
            return "Low"
    
    def _determine_hunting_priority(self,
                                  quality_assessment: AdvancedQualityAssessment,
                                  ttp_analysis: EnhancedThreatHuntingAnalysis) -> str:
        """Determine hunting priority based on both analyses."""
        
        # Prioritize TTP analysis hunting priority
        if ttp_analysis.hunting_priority == "Critical":
            return "Critical"
        elif ttp_analysis.hunting_priority == "High":
            return "High"
        elif quality_assessment.hunting_priority == "High":
            return "High"
        elif ttp_analysis.hunting_priority == "Medium":
            return "Medium"
        else:
            return "Low"
    
    def _calculate_confidence_score(self,
                                  quality_assessment: AdvancedQualityAssessment,
                                  ttp_analysis: EnhancedThreatHuntingAnalysis) -> float:
        """Calculate confidence score based on both analyses."""
        
        # Weighted average of confidence scores
        quality_confidence = quality_assessment.hunting_confidence
        ttp_confidence = ttp_analysis.overall_confidence
        
        weighted_confidence = (
            quality_confidence * self.integration_weights["quality_assessment"] +
            ttp_confidence * self.integration_weights["ttp_analysis"]
        )
        
        return min(weighted_confidence, 1.0)
    
    def _count_total_artifacts(self, quality_assessment: AdvancedQualityAssessment) -> int:
        """Count total artifacts found in quality assessment."""
        total = 0
        for category_score in quality_assessment.artifact_breakdown.values():
            total += len(category_score.artifacts_found)
        return total
    
    def _get_platforms_covered(self,
                              quality_assessment: AdvancedQualityAssessment,
                              ttp_analysis: EnhancedThreatHuntingAnalysis) -> List[str]:
        """Get list of platforms covered by both analyses."""
        platforms = set()
        
        # Add platforms from quality assessment
        for platform, score in [
            ("Windows", quality_assessment.windows_artifacts_score),
            ("Linux", quality_assessment.linux_artifacts_score),
            ("macOS", quality_assessment.macos_artifacts_score),
            ("Cloud", quality_assessment.cloud_artifacts_score),
            ("Container", quality_assessment.container_artifacts_score)
        ]:
            if score > 0:
                platforms.add(platform)
        
        # Add platforms from TTP analysis
        for platform, techniques in ttp_analysis.techniques_by_platform.items():
            if techniques:
                platforms.add(platform.title())
        
        return list(platforms)
    
    def _count_critical_artifacts(self,
                                quality_assessment: AdvancedQualityAssessment,
                                ttp_analysis: EnhancedThreatHuntingAnalysis) -> int:
        """Count critical artifacts from both analyses."""
        critical_count = 0
        
        # Count from quality assessment
        for category_score in quality_assessment.artifact_breakdown.values():
            if category_score.criticality.value == "Critical":
                critical_count += len(category_score.artifacts_found)
        
        # Count from TTP analysis
        critical_techniques = ttp_analysis.techniques_by_criticality.get("Critical", [])
        critical_count += len(critical_techniques)
        
        return critical_count
    
    def _count_high_artifacts(self,
                             quality_assessment: AdvancedQualityAssessment,
                             ttp_analysis: EnhancedThreatHuntingAnalysis) -> int:
        """Count high-priority artifacts from both analyses."""
        high_count = 0
        
        # Count from quality assessment
        for category_score in quality_assessment.artifact_breakdown.values():
            if category_score.criticality.value == "High":
                high_count += len(category_score.artifacts_found)
        
        # Count from TTP analysis
        high_techniques = ttp_analysis.techniques_by_criticality.get("High", [])
        high_count += len(high_techniques)
        
        return high_count
    
    def _generate_integrated_recommendations(self,
                                            quality_assessment: AdvancedQualityAssessment,
                                            ttp_analysis: EnhancedThreatHuntingAnalysis) -> List[str]:
        """Generate integrated recommendations from both analyses."""
        recommendations = []
        
        # Add quality assessment recommendations
        recommendations.extend(quality_assessment.recommendations)
        
        # Add TTP-specific recommendations
        if ttp_analysis.total_techniques < 2:
            recommendations.append("Include more specific MITRE ATT&CK techniques")
        
        if not ttp_analysis.threat_actors:
            recommendations.append("Add threat actor context and attribution")
        
        if not ttp_analysis.malware_families:
            recommendations.append("Include malware family information")
        
        # Add platform-specific recommendations
        if quality_assessment.windows_artifacts_score < 30:
            recommendations.append("Expand Windows artifact coverage")
        
        if quality_assessment.linux_artifacts_score < 30:
            recommendations.append("Add Linux/Unix artifact coverage")
        
        if quality_assessment.cloud_artifacts_score < 30:
            recommendations.append("Include cloud environment artifacts")
        
        return list(set(recommendations))  # Remove duplicates
    
    def _generate_integrated_hunting_guidance(self,
                                            quality_assessment: AdvancedQualityAssessment,
                                            ttp_analysis: EnhancedThreatHuntingAnalysis) -> List[str]:
        """Generate integrated hunting guidance from both analyses."""
        guidance = []
        
        # Add quality assessment guidance
        guidance.extend(quality_assessment.hunting_guidance)
        
        # Add TTP analysis guidance
        guidance.extend(ttp_analysis.hunting_guidance)
        
        # Add priority-based guidance
        if ttp_analysis.hunting_priority == "Critical":
            guidance.append("CRITICAL: Immediate hunting required - high-value artifacts detected")
        elif ttp_analysis.hunting_priority == "High":
            guidance.append("HIGH: Prioritize for hunting - multiple high-value techniques found")
        
        return list(set(guidance))  # Remove duplicates
    
    def _generate_next_steps(self, overall_score: int, hunting_priority: str, critical_artifacts: int) -> List[str]:
        """Generate next steps based on analysis results."""
        next_steps = []
        
        if hunting_priority == "Critical":
            next_steps.extend([
                "Immediately implement hunting queries for critical artifacts",
                "Alert security team for rapid response",
                "Review and update detection rules",
                "Conduct threat hunting session within 24 hours"
            ])
        elif hunting_priority == "High":
            next_steps.extend([
                "Schedule hunting session within 48 hours",
                "Update detection rules and monitoring",
                "Review existing security controls",
                "Consider threat intelligence sharing"
            ])
        elif hunting_priority == "Medium":
            next_steps.extend([
                "Include in regular hunting rotation",
                "Review for additional context",
                "Update documentation and playbooks",
                "Monitor for related activity"
            ])
        else:
            next_steps.extend([
                "Archive for future reference",
                "Review for potential improvements",
                "Consider for training materials"
            ])
        
        return next_steps
    
    def _create_default_result(self, article_id: int, article_title: str, source_url: str) -> IntegratedQualityResult:
        """Create default result when analysis fails."""
        return IntegratedQualityResult(
            article_id=article_id,
            article_title=article_title,
            source_url=source_url,
            quality_assessment=AdvancedQualityAssessment(
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
                hunting_guidance=["Analysis failed"],
                overall_quality_score=0,
                quality_level="Low",
                recommendations=["Analysis failed - review manually"]
            ),
            ttp_analysis=EnhancedThreatHuntingAnalysis(
                article_id=article_id,
                total_techniques=0,
                techniques_by_category={},
                techniques_by_platform={},
                techniques_by_criticality={},
                threat_actors=[],
                malware_families=[],
                attack_vectors=[],
                overall_confidence=0.0,
                hunting_priority="Low",
                content_quality_score=0.0,
                artifact_coverage={
                    "windows": 0,
                    "linux": 0,
                    "macos": 0,
                    "cloud": 0,
                    "container": 0
                },
                hunting_guidance=["Analysis failed"],
                detection_queries=[]
            ),
            overall_score=0,
            overall_quality_level="Low",
            hunting_priority="Low",
            confidence_score=0.0,
            total_artifacts_found=0,
            total_techniques_found=0,
            platforms_covered=[],
            critical_artifacts=0,
            high_artifacts=0,
            recommendations=["Analysis failed - review content manually"],
            hunting_guidance=["Analysis failed"],
            next_steps=["Review content manually"]
        )
    
    def generate_integrated_report(self, result: IntegratedQualityResult) -> str:
        """Generate comprehensive integrated analysis report."""
        report = []
        report.append("🔍 Integrated Quality Assessment Report")
        report.append("=" * 60)
        report.append(f"Article ID: {result.article_id}")
        report.append(f"Title: {result.article_title}")
        report.append(f"Source: {result.source_url}")
        report.append("")
        
        report.append("📊 Overall Assessment:")
        report.append("-" * 25)
        report.append(f"Overall Score: {result.overall_score}/100")
        report.append(f"Quality Level: {result.overall_quality_level}")
        report.append(f"Hunting Priority: {result.hunting_priority}")
        report.append(f"Confidence Score: {result.confidence_score:.2f}")
        report.append("")
        
        report.append("📈 Summary Statistics:")
        report.append("-" * 25)
        report.append(f"Total Artifacts Found: {result.total_artifacts_found}")
        report.append(f"Total Techniques Found: {result.total_techniques_found}")
        report.append(f"Critical Artifacts: {result.critical_artifacts}")
        report.append(f"High-Priority Artifacts: {result.high_artifacts}")
        report.append(f"Platforms Covered: {', '.join(result.platforms_covered) if result.platforms_covered else 'None'}")
        report.append("")
        
        report.append("🎯 Quality Assessment Breakdown:")
        report.append("-" * 35)
        report.append(f"Artifact Coverage: {result.quality_assessment.artifact_coverage_score}/100")
        report.append(f"Technical Depth: {result.quality_assessment.technical_depth_score}/100")
        report.append(f"Actionable Intelligence: {result.quality_assessment.actionable_intelligence_score}/100")
        report.append(f"Threat Context: {result.quality_assessment.threat_context_score}/100")
        report.append(f"Detection Quality: {result.quality_assessment.detection_quality_score}/100")
        report.append("")
        
        report.append("🖥️ Platform Coverage:")
        report.append("-" * 20)
        report.append(f"Windows: {result.quality_assessment.windows_artifacts_score}/100")
        report.append(f"Linux: {result.quality_assessment.linux_artifacts_score}/100")
        report.append(f"macOS: {result.quality_assessment.macos_artifacts_score}/100")
        report.append(f"Cloud: {result.quality_assessment.cloud_artifacts_score}/100")
        report.append(f"Container: {result.quality_assessment.container_artifacts_score}/100")
        report.append("")
        
        if result.ttp_analysis.threat_actors:
            report.append("🎭 Threat Actors:")
            report.append("-" * 15)
            for actor in result.ttp_analysis.threat_actors:
                report.append(f"• {actor}")
            report.append("")
        
        if result.ttp_analysis.malware_families:
            report.append("🦠 Malware Families:")
            report.append("-" * 18)
            for malware in result.ttp_analysis.malware_families:
                report.append(f"• {malware}")
            report.append("")
        
        if result.ttp_analysis.attack_vectors:
            report.append("🎯 Attack Vectors:")
            report.append("-" * 16)
            for vector in result.ttp_analysis.attack_vectors:
                report.append(f"• {vector}")
            report.append("")
        
        report.append("💡 Hunting Guidance:")
        report.append("-" * 18)
        for guidance in result.hunting_guidance:
            report.append(f"• {guidance}")
        report.append("")
        
        report.append("🔧 Recommendations:")
        report.append("-" * 15)
        for rec in result.recommendations:
            report.append(f"• {rec}")
        report.append("")
        
        report.append("📋 Next Steps:")
        report.append("-" * 12)
        for step in result.next_steps:
            report.append(f"• {step}")
        report.append("")
        
        report.append("✅ Integrated Analysis Complete!")
        
        return "\n".join(report)


# Convenience function for easy integration
def analyze_content_integrated(content: str, 
                             article_id: int = 0,
                             article_title: str = "",
                             source_url: str = "") -> IntegratedQualityResult:
    """
    Convenience function to perform integrated content analysis.
    
    Args:
        content: Article content to analyze
        article_id: Article identifier
        article_title: Article title
        source_url: Source URL
        
    Returns:
        IntegratedQualityResult with comprehensive analysis
    """
    system = IntegratedQualitySystem()
    return system.analyze_content(content, article_id, article_title, source_url)
