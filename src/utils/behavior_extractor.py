"""
SecureBERT-based behavior extraction for threat intelligence articles.

This module extracts attacker behaviors, techniques, and tactics from threat intelligence
content using SecureBERT, providing concise, focused information for SIGMA rule generation.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

logger = logging.getLogger(__name__)

@dataclass
class BehaviorExtractionResult:
    """Result of behavior extraction from threat intelligence content."""
    techniques: List[str]
    tactics: List[str]
    behaviors: List[str]
    tools: List[str]
    processes: List[str]
    confidence_scores: Dict[str, float]
    extraction_method: str
    processing_time: float

class SecureBERTBehaviorExtractor:
    """
    Extract attacker behaviors and techniques using SecureBERT.
    
    SecureBERT is a cybersecurity-specific BERT model trained on threat intelligence
    and attack techniques, making it ideal for extracting structured behavioral patterns.
    """
    
    def __init__(self, model_name: str = "ehsanaghaei/SecureBERT", use_gpu: bool = False):
        """
        Initialize the SecureBERT behavior extractor.
        
        Args:
            model_name: Hugging Face model name for SecureBERT
            use_gpu: Whether to use GPU acceleration
        """
        self.model_name = model_name
        self.device = "cuda" if use_gpu and torch.cuda.is_available() else "cpu"
        self.tokenizer = None
        self.model = None
        self._load_model()
        
        # MITRE ATT&CK technique patterns for validation
        self.technique_patterns = {
            'T1055': r'(process hollowing|process injection|dll injection)',
            'T1059': r'(powershell|cmd|command line|script)',
            'T1071': r'(http|https|dns|network communication)',
            'T1083': r'(file|directory|folder enumeration)',
            'T1105': r'(ingress tool transfer|download|upload)',
            'T1112': r'(modify registry|registry modification)',
            'T1134': r'(access token manipulation|token impersonation)',
            'T1140': r'(deobfuscate|decode|decrypt)',
            'T1204': r'(user execution|malicious file)',
            'T1566': r'(phishing|spearphishing|social engineering)',
            'T1573': r'(encrypted channel|encrypted communication)',
            'T1027': r'(obfuscated|encoded|encrypted)',
            'T1036': r'(masquerading|impersonation|spoofing)',
            'T1049': r'(system network connections|netstat|network discovery)',
            'T1057': r'(process discovery|tasklist|ps)',
            'T1082': r'(system information discovery|systeminfo|whoami)',
            'T1087': r'(account discovery|net user|user enumeration)',
            'T1135': r'(network share discovery|net share|smb)',
            'T1201': r'(password policy discovery|net accounts)',
            'T1482': r'(domain trust discovery|nltest|domain enumeration)'
        }
        
        # Common attack tools and processes
        self.tool_patterns = {
            'tools': r'(mimikatz|metasploit|empire|cobalt strike|bloodhound|responder|impacket|psexec|wmic|regsvr32|rundll32|certutil|bitsadmin|powershell|cmd|bash|sh)',
            'processes': r'(powershell\.exe|cmd\.exe|wmic\.exe|regsvr32\.exe|rundll32\.exe|certutil\.exe|bitsadmin\.exe|mshta\.exe|wscript\.exe|cscript\.exe|notepad\.exe|calc\.exe)',
            'files': r'(\.ps1|\.bat|\.cmd|\.vbs|\.js|\.hta|\.exe|\.dll|\.scr|\.lnk)',
            'registry': r'(HKEY_|HKLM|HKU|HKCU|HKCR|SOFTWARE|SYSTEM|SAM|SECURITY)',
            'network': r'(tcp|udp|http|https|dns|smb|ldap|kerberos|ntlm|ftp|ssh|telnet|rdp|vnc)'
        }
    
    def _load_model(self):
        """Load the SecureBERT model and tokenizer."""
        try:
            logger.info(f"Loading SecureBERT model: {self.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.to(self.device)
            self.model.eval()
            logger.info(f"SecureBERT model loaded successfully on {self.device}")
        except Exception as e:
            logger.error(f"Failed to load SecureBERT model: {e}")
            # Fallback to pattern-based extraction
            self.model = None
            self.tokenizer = None
    
    def extract_behaviors(self, content: str, title: str = "") -> BehaviorExtractionResult:
        """
        Extract attacker behaviors and techniques from threat intelligence content.
        
        Args:
            content: Article content to analyze
            title: Article title for additional context
            
        Returns:
            BehaviorExtractionResult with extracted behaviors and techniques
        """
        import time
        start_time = time.time()
        
        # Combine title and content for analysis
        full_text = f"{title}\n\n{content}" if title else content
        
        if self.model and self.tokenizer:
            # Use SecureBERT for advanced extraction
            techniques, tactics, behaviors, tools, processes, confidence_scores = self._extract_with_securebert(full_text)
            extraction_method = "securebert"
        else:
            # Fallback to pattern-based extraction
            techniques, tactics, behaviors, tools, processes, confidence_scores = self._extract_with_patterns(full_text)
            extraction_method = "pattern_based"
        
        processing_time = time.time() - start_time
        
        return BehaviorExtractionResult(
            techniques=techniques,
            tactics=tactics,
            behaviors=behaviors,
            tools=tools,
            processes=processes,
            confidence_scores=confidence_scores,
            extraction_method=extraction_method,
            processing_time=processing_time
        )
    
    def _extract_with_securebert(self, text: str) -> Tuple[List[str], List[str], List[str], List[str], List[str], Dict[str, float]]:
        """Extract behaviors using SecureBERT model."""
        try:
            # Tokenize input
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                max_length=512,
                truncation=True,
                padding=True
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.model(**inputs)
                predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
            # Extract top predictions
            top_predictions = torch.topk(predictions, k=10, dim=-1)
            
            # Map predictions to behaviors (this would need to be customized based on SecureBERT's training)
            techniques = []
            tactics = []
            behaviors = []
            tools = []
            processes = []
            confidence_scores = {}
            
            # For now, combine with pattern-based extraction
            pattern_results = self._extract_with_patterns(text)
            techniques.extend(pattern_results[0])
            tactics.extend(pattern_results[1])
            behaviors.extend(pattern_results[2])
            tools.extend(pattern_results[3])
            processes.extend(pattern_results[4])
            
            # Add confidence scores from SecureBERT
            for i, (score, idx) in enumerate(zip(top_predictions.values[0], top_predictions.indices[0])):
                confidence_scores[f"securebert_prediction_{i}"] = float(score)
            
            return techniques, tactics, behaviors, tools, processes, confidence_scores
            
        except Exception as e:
            logger.error(f"SecureBERT extraction failed: {e}")
            # Fallback to pattern-based extraction
            return self._extract_with_patterns(text)
    
    def _extract_with_patterns(self, text: str) -> Tuple[List[str], List[str], List[str], List[str], List[str], Dict[str, float]]:
        """Extract behaviors using pattern matching."""
        text_lower = text.lower()
        
        techniques = []
        tactics = []
        behaviors = []
        tools = []
        processes = []
        confidence_scores = {}
        
        # Extract MITRE ATT&CK techniques
        for technique_id, pattern in self.technique_patterns.items():
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                techniques.append(f"{technique_id}: {matches[0]}")
                confidence_scores[f"technique_{technique_id}"] = 0.8
        
        # Extract tools and processes
        for category, pattern in self.tool_patterns.items():
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                if category == 'tools':
                    tools.extend(matches)
                elif category == 'processes':
                    processes.extend(matches)
                elif category == 'files':
                    behaviors.extend([f"file_type: {match}" for match in matches])
                elif category == 'registry':
                    behaviors.extend([f"registry_access: {match}" for match in matches])
                elif category == 'network':
                    behaviors.extend([f"network_protocol: {match}" for match in matches])
                
                confidence_scores[f"pattern_{category}"] = 0.7
        
        # Extract common attack behaviors
        behavior_patterns = {
            'lateral_movement': r'(lateral movement|pivot|jump|move|spread)',
            'persistence': r'(persistence|maintain|establish|create|install)',
            'privilege_escalation': r'(privilege escalation|elevate|escalate|admin|root|system)',
            'defense_evasion': r'(evasion|bypass|avoid|hide|obfuscate|encrypt)',
            'credential_access': r'(credential|password|hash|token|key|certificate)',
            'discovery': r'(discovery|enumerate|scan|probe|reconnaissance|information gathering)',
            'collection': r'(collect|gather|steal|exfiltrate|harvest)',
            'command_control': r'(command and control|c2|c&c|communication|beacon)',
            'exfiltration': r'(exfiltration|exfil|data theft|steal data|leak)',
            'impact': r'(impact|damage|destroy|disrupt|denial of service|dos)'
        }
        
        for behavior_type, pattern in behavior_patterns.items():
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                behaviors.append(f"{behavior_type}: {matches[0]}")
                confidence_scores[f"behavior_{behavior_type}"] = 0.6
        
        # Extract MITRE ATT&CK tactics
        tactic_patterns = {
            'initial_access': r'(initial access|entry point|vector|phishing|spearphishing|exploit)',
            'execution': r'(execution|run|execute|launch|start|invoke)',
            'persistence': r'(persistence|maintain|establish|create|install|schedule)',
            'privilege_escalation': r'(privilege escalation|elevate|escalate|admin|root|system)',
            'defense_evasion': r'(evasion|bypass|avoid|hide|obfuscate|encrypt|masquerade)',
            'credential_access': r'(credential|password|hash|token|key|certificate|authentication)',
            'discovery': r'(discovery|enumerate|scan|probe|reconnaissance|information gathering)',
            'lateral_movement': r'(lateral movement|pivot|jump|move|spread|network)',
            'collection': r'(collect|gather|steal|exfiltrate|harvest|data)',
            'command_control': r'(command and control|c2|c&c|communication|beacon|channel)',
            'exfiltration': r'(exfiltration|exfil|data theft|steal data|leak|transfer)',
            'impact': r'(impact|damage|destroy|disrupt|denial of service|dos|manipulation)'
        }
        
        for tactic_name, pattern in tactic_patterns.items():
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            if matches:
                tactics.append(f"{tactic_name}: {matches[0]}")
                confidence_scores[f"tactic_{tactic_name}"] = 0.6
        
        # Remove duplicates and limit results
        techniques = list(set(techniques))[:10]
        tactics = list(set(tactics))[:10]
        behaviors = list(set(behaviors))[:15]
        tools = list(set(tools))[:10]
        processes = list(set(processes))[:10]
        
        return techniques, tactics, behaviors, tools, processes, confidence_scores
    
    def format_for_sigma(self, result: BehaviorExtractionResult) -> str:
        """
        Format the extraction result for SIGMA rule generation.
        
        Args:
            result: BehaviorExtractionResult to format
            
        Returns:
            Formatted string for SIGMA prompt
        """
        output = []
        
        if result.techniques:
            output.append("**MITRE ATT&CK Techniques:**")
            for technique in result.techniques:
                output.append(f"- {technique}")
            output.append("")
        
        if result.tactics:
            output.append("**Attack Tactics:**")
            for tactic in result.tactics:
                output.append(f"- {tactic}")
            output.append("")
        
        if result.behaviors:
            output.append("**Attack Behaviors:**")
            for behavior in result.behaviors:
                output.append(f"- {behavior}")
            output.append("")
        
        if result.tools:
            output.append("**Tools Used:**")
            for tool in result.tools:
                output.append(f"- {tool}")
            output.append("")
        
        if result.processes:
            output.append("**Processes Involved:**")
            for process in result.processes:
                output.append(f"- {process}")
            output.append("")
        
        # Add confidence information
        if result.confidence_scores:
            avg_confidence = sum(result.confidence_scores.values()) / len(result.confidence_scores)
            output.append(f"**Extraction Confidence:** {avg_confidence:.2f}")
            output.append(f"**Method:** {result.extraction_method}")
            output.append(f"**Processing Time:** {result.processing_time:.2f}s")
        
        return "\n".join(output)


def extract_attacker_behaviors(content: str, title: str = "") -> BehaviorExtractionResult:
    """
    Convenience function to extract attacker behaviors from threat intelligence content.
    
    Args:
        content: Article content to analyze
        title: Article title for additional context
        
    Returns:
        BehaviorExtractionResult with extracted behaviors and techniques
    """
    extractor = SecureBERTBehaviorExtractor()
    return extractor.extract_behaviors(content, title)
