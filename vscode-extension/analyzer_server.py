#!/usr/bin/env python3
"""
Server script for VSCode extension to analyze Solidity code.
Reads JSON from stdin and outputs analysis results as JSON.
"""

import sys
import json
import os
from pathlib import Path

# Add the parent directory to the path to import the detector
# Try multiple possible paths
script_dir = Path(__file__).parent
possible_paths = [
    script_dir.parent,  # Parent of vscode-extension
    script_dir.parent / 'src',  # Direct src path
    script_dir,  # Current directory
]

for p in possible_paths:
    if p.exists():
        sys.path.insert(0, str(p))

try:
    from src.detector import ReentrancyDetector
    from src.models import Severity
except ImportError:
    # Try alternative import path
    try:
        from detector import ReentrancyDetector
        from models import Severity
    except ImportError:
        print(json.dumps({
            "error": "Could not import detector module. Make sure the analyzer is properly installed.",
            "parse_errors": ["Import error: detector module not found"]
        }), file=sys.stderr)
        sys.exit(1)


def severity_from_string(s: str) -> Severity:
    """
    Convert string to Severity enum.
    
    Args:
        s: Severity string (case-insensitive)
        
    Returns:
        Severity enum value, defaults to LOW if invalid
    """
    if not isinstance(s, str):
        return Severity.LOW
        
    mapping = {
        'critical': Severity.CRITICAL,
        'high': Severity.HIGH,
        'medium': Severity.MEDIUM,
        'low': Severity.LOW,
        'info': Severity.INFO
    }
    return mapping.get(s.lower(), Severity.LOW)


def main():
    """Main entry point for the analyzer server."""
    # Parse command line arguments
    severity_threshold = Severity.LOW
    if len(sys.argv) > 2 and sys.argv[1] == '--severity':
        severity_threshold = severity_from_string(sys.argv[2])

    # Read input from stdin with size limit
    MAX_INPUT_SIZE = 50 * 1024 * 1024  # 50MB
    try:
        stdin_content = sys.stdin.read(MAX_INPUT_SIZE)
        if len(stdin_content) >= MAX_INPUT_SIZE:
            print(json.dumps({
                "error": "Input too large",
                "parse_errors": [f"Input exceeds maximum size of {MAX_INPUT_SIZE / 1024 / 1024}MB"]
            }), file=sys.stderr)
            sys.exit(1)
        
        input_data = json.loads(stdin_content)
        source_code = input_data.get('source', '')
        filename = input_data.get('filename', 'contract.sol')
        
        # Validate filename to prevent path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            filename = 'contract.sol'  # Sanitize filename
    except json.JSONDecodeError as e:
        print(json.dumps({
            "error": f"Invalid JSON input: {e}",
            "parse_errors": [str(e)]
        }), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            "error": f"Error reading input: {e}",
            "parse_errors": [str(e)]
        }), file=sys.stderr)
        sys.exit(1)

    if not source_code:
        print(json.dumps({
            "file": filename,
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            },
            "vulnerabilities": [],
            "parse_errors": ["No source code provided"]
        }))
        return

    # Configure and run detector
    try:
        config = {
            'severity_threshold': severity_threshold,
            'include_info': severity_threshold == Severity.INFO
        }
        detector = ReentrancyDetector(config)
        result = detector.analyze_source(source_code, filename)

        # Convert to JSON-serializable format
        output = result.to_dict()
        print(json.dumps(output))
    except Exception as e:
        print(json.dumps({
            "error": f"Analysis error: {e}",
            "parse_errors": [str(e)],
            "file": filename,
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            },
            "vulnerabilities": []
        }), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
