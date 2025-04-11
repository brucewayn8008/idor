"""
Logger module for handling output and logging functionality
"""

import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, Optional

class ScanLogger:
    """Handles logging and output for the scanner."""
    
    def __init__(
        self,
        output_dir: str,
        verbose: bool = False,
        log_file: str = "scan.log"
    ):
        """
        Initialize the logger.
        
        Args:
            output_dir: Directory to store log files
            verbose: Whether to enable verbose output
            log_file: Name of the log file
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup file logging
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.output_dir / log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("IDOR-BAC-Hunter")
        self.findings: list = []
    
    def log_finding(
        self,
        endpoint: str,
        vulnerability_type: str,
        details: Dict[str, Any],
        severity: str = "Medium"
    ) -> None:
        """
        Log a security finding.
        
        Args:
            endpoint: The affected endpoint
            vulnerability_type: Type of vulnerability (IDOR/BAC)
            details: Additional details about the finding
            severity: Severity level of the finding
        """
        finding = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": endpoint,
            "type": vulnerability_type,
            "severity": severity,
            "details": details
        }
        
        self.findings.append(finding)
        self.logger.warning(
            f"Found {vulnerability_type} in {endpoint} - {details.get('description', '')}"
        )
    
    def log_error(self, message: str, error: Optional[Exception] = None) -> None:
        """
        Log an error message.
        
        Args:
            message: Error message to log
            error: Optional exception object
        """
        if error:
            self.logger.error(f"{message}: {str(error)}")
        else:
            self.logger.error(message)
    
    def save_results(self) -> None:
        """Save all findings to a JSON file."""
        if not self.findings:
            self.logger.info("No vulnerabilities found in this scan")
            return
            
        output_file = self.output_dir / f"findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(output_file, 'w') as f:
            json.dump(
                {
                    "scan_time": datetime.now().isoformat(),
                    "total_findings": len(self.findings),
                    "findings": self.findings
                },
                f,
                indent=2
            )
            
        self.logger.info(f"Saved {len(self.findings)} findings to {output_file}")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure results are saved."""
        self.save_results() 