#!/usr/bin/env python3
"""
IDOR-BAC Hunter - A security testing tool for detecting IDOR and BAC vulnerabilities
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from core.session_loader import SessionManager
from core.request_handler import RequestHandler
from core.detector import IdorDetector

def setup_argparse() -> argparse.ArgumentParser:
    """Configure and return the argument parser for CLI options."""
    parser = argparse.ArgumentParser(
        description='IDOR-BAC Hunter - Detect IDOR and BAC vulnerabilities'
    )
    parser.add_argument(
        '-s', '--sitemap',
        required=True,
        type=str,
        help='Path to Burp Suite sitemap export file'
    )
    parser.add_argument(
        '-c', '--config',
        required=True,
        type=str,
        help='Path to sessions configuration file'
    )
    parser.add_argument(
        '-o', '--output',
        default='output/findings.json',
        type=str,
        help='Output file for findings (default: output/findings.json)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    return parser

def load_urls(sitemap_path: str) -> List[str]:
    """
    Load URLs from sitemap file.
    
    Args:
        sitemap_path: Path to the sitemap file
        
    Returns:
        List of URLs to test
    """
    try:
        with open(sitemap_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Sitemap file not found: {sitemap_path}")
        sys.exit(1)

def main():
    """Main entry point for IDOR-BAC Hunter."""
    parser = setup_argparse()
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    if args.verbose:
        print("Initializing IDOR-BAC Hunter...")

    # Initialize components
    session_manager = SessionManager(args.config)
    request_handler = RequestHandler(timeout=10)
    detector = IdorDetector(session_manager, request_handler)

    # Load URLs
    urls = load_urls(args.sitemap)
    if args.verbose:
        print(f"Loaded {len(urls)} URLs to test")
        print(f"Using {len(session_manager.list_users())} user sessions")

    # Start scanning
    print("\nStarting IDOR vulnerability scan...")
    findings = detector.scan_urls(urls, verbose=args.verbose)

    # Save results
    detector.save_findings(args.output)
    print(f"\nScan complete! Found {len(findings)} potential vulnerabilities")
    print(f"Results saved to: {args.output}")

if __name__ == "__main__":
    main() 