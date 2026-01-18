"""
Main reentrancy detection engine.
Orchestrates parsing and pattern detection.
"""

import os
import time
from pathlib import Path
from typing import List, Optional, Union, Dict, Any

from .models import (
    Contract, Vulnerability, AnalysisResult, ScanResult,
    Severity, CodeSnippet
)
from .parser import SolidityParser
from .patterns import ReentrancyPatterns

# Constants
DEFAULT_MAX_FILE_SIZE = 1024 * 1024  # 1MB
DEFAULT_SEVERITY_THRESHOLD = Severity.LOW
DEFAULT_EXCLUDE_PATTERNS = ['node_modules', 'test', 'mock', 'Mock']


class ReentrancyDetector:
    """
    Main detector class for finding reentrancy vulnerabilities in Solidity contracts.

    Usage:
        detector = ReentrancyDetector()
        result = detector.analyze_file("contract.sol")
        for vuln in result.vulnerabilities:
            print(f"{vuln.severity}: {vuln.description}")
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the detector.

        Args:
            config: Optional configuration dictionary with keys:
                - severity_threshold: Minimum severity to report (default: LOW)
                - include_info: Include informational findings (default: False)
                - max_file_size: Maximum file size to analyze in bytes (default: 1MB)

        Raises:
            ValueError: If configuration values are invalid
        """
        self.config = config or {}
        self.severity_threshold = self.config.get('severity_threshold', DEFAULT_SEVERITY_THRESHOLD)
        self.include_info = self.config.get('include_info', False)
        self.max_file_size = self.config.get('max_file_size', DEFAULT_MAX_FILE_SIZE)

        # Validate configuration
        if not isinstance(self.severity_threshold, Severity):
            raise ValueError(f"Invalid severity_threshold: {self.severity_threshold}")
        if not isinstance(self.max_file_size, int) or self.max_file_size <= 0:
            raise ValueError(f"Invalid max_file_size: {self.max_file_size}")

        self.parser = SolidityParser()

    def analyze_file(self, file_path: Union[str, Path]) -> AnalysisResult:
        """
        Analyze a single Solidity file for reentrancy vulnerabilities.

        Args:
            file_path: Path to the Solidity file

        Returns:
            AnalysisResult containing detected vulnerabilities

        Raises:
            ValueError: If file_path is invalid
        """
        file_path = Path(file_path)
        result = AnalysisResult(file_path=str(file_path))
        start_time = time.time()

        # Validate file existence
        if not file_path.exists():
            result.parse_errors.append(f"File not found: {file_path}")
            return result

        # Validate file extension
        if file_path.suffix != '.sol':
            result.parse_errors.append(f"Not a Solidity file: {file_path}")
            return result

        # Validate file size
        try:
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                result.parse_errors.append(
                    f"File too large: {file_path} ({file_size / 1024 / 1024:.2f}MB > "
                    f"{self.max_file_size / 1024 / 1024:.2f}MB)"
                )
                return result
        except OSError as e:
            result.parse_errors.append(f"Error accessing file: {e}")
            return result

        # Read file content
        try:
            source_code = file_path.read_text(encoding='utf-8')
        except UnicodeDecodeError as e:
            result.parse_errors.append(f"File encoding error: {e}")
            return result
        except IOError as e:
            result.parse_errors.append(f"Error reading file: {e}")
            return result

        # Analyze source code
        return self._analyze_source_code(source_code, result, start_time)

    def analyze_source(self, source_code: str, filename: str = "contract.sol") -> AnalysisResult:
        """
        Analyze Solidity source code directly.

        Args:
            source_code: Solidity source code string
            filename: Optional filename for reporting

        Returns:
            AnalysisResult containing detected vulnerabilities

        Raises:
            ValueError: If source_code is empty or invalid
        """
        if not isinstance(source_code, str):
            raise ValueError("source_code must be a string")
        if not source_code.strip():
            result = AnalysisResult(file_path=filename)
            result.parse_errors.append("Empty source code provided")
            return result

        result = AnalysisResult(file_path=filename)
        start_time = time.time()
        return self._analyze_source_code(source_code, result, start_time)

    def _analyze_source_code(
        self,
        source_code: str,
        result: AnalysisResult,
        start_time: float
    ) -> AnalysisResult:
        """
        Internal method to analyze source code and populate result.

        Args:
            source_code: Solidity source code string
            result: AnalysisResult to populate
            start_time: Analysis start time for timing

        Returns:
            AnalysisResult with vulnerabilities populated
        """
        # Parse contracts
        try:
            contracts = self.parser.parse(source_code)
            result.contracts = contracts
        except Exception as e:
            result.parse_errors.append(f"Parse error: {e}")
            return result

        # Run detection on each contract
        for contract in contracts:
            vulnerabilities = self._analyze_contract(contract)
            result.vulnerabilities.extend(vulnerabilities)

        # Filter by severity threshold
        result.vulnerabilities = [
            v for v in result.vulnerabilities
            if v.severity >= self.severity_threshold or
               (v.severity == Severity.INFO and self.include_info)
        ]

        # Sort by severity (most severe first)
        result.vulnerabilities.sort(key=lambda v: v.severity, reverse=True)

        result.analysis_time_ms = (time.time() - start_time) * 1000
        return result

    def scan_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        exclude_patterns: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Scan a directory for Solidity files and analyze them.

        Args:
            directory: Path to directory
            recursive: Whether to scan subdirectories
            exclude_patterns: List of patterns to exclude (e.g., ['test', 'mock'])

        Returns:
            ScanResult with results from all files

        Raises:
            ValueError: If directory path is invalid
        """
        directory = Path(directory)
        exclude_patterns = exclude_patterns or DEFAULT_EXCLUDE_PATTERNS

        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory}")

        scan_result = ScanResult()
        start_time = time.time()

        # Find all .sol files
        try:
            if recursive:
                sol_files = list(directory.rglob('*.sol'))
            else:
                sol_files = list(directory.glob('*.sol'))
        except PermissionError as e:
            scan_result.results.append(
                AnalysisResult(
                    file_path=str(directory),
                    parse_errors=[f"Permission denied accessing directory: {e}"]
                )
            )
            return scan_result

        # Filter excluded patterns
        def should_exclude(path: Path) -> bool:
            """Check if a path should be excluded based on patterns."""
            path_str = str(path)
            return any(pattern in path_str for pattern in exclude_patterns)

        sol_files = [f for f in sol_files if not should_exclude(f)]

        # Analyze each file
        for sol_file in sol_files:
            try:
                result = self.analyze_file(sol_file)
                scan_result.results.append(result)
                scan_result.files_scanned += 1
                scan_result.total_contracts += len(result.contracts)
            except Exception as e:
                # Continue with other files even if one fails
                error_result = AnalysisResult(
                    file_path=str(sol_file),
                    parse_errors=[f"Error analyzing file: {e}"]
                )
                scan_result.results.append(error_result)
                scan_result.files_scanned += 1

        scan_result.total_analysis_time_ms = (time.time() - start_time) * 1000
        return scan_result

    def _analyze_contract(self, contract: Contract) -> List[Vulnerability]:
        """
        Run all detection patterns on a contract.

        Args:
            contract: Parsed contract to analyze

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []

        # Helper to get code snippets
        def get_snippet(line: int, context: int = 3) -> CodeSnippet:
            return self.parser.get_code_snippet(line, context)

        # Check each function
        for function in contract.functions:
            # Pattern 1: State change after external call (Critical)
            vulns = ReentrancyPatterns.detect_state_change_after_call(
                function, contract, get_snippet
            )
            vulnerabilities.extend(vulns)

            # Pattern 2: External call in loop (High)
            vulns = ReentrancyPatterns.detect_external_call_in_loop(
                function, contract, get_snippet
            )
            vulnerabilities.extend(vulns)

            # Pattern 3: Missing reentrancy guard (Medium)
            vulns = ReentrancyPatterns.detect_missing_reentrancy_guard(
                function, contract, self.parser.has_reentrancy_modifier, get_snippet
            )
            vulnerabilities.extend(vulns)

            # Pattern 4: Delegatecall risks (High)
            vulns = ReentrancyPatterns.detect_delegatecall_reentrancy(
                function, contract, get_snippet
            )
            vulnerabilities.extend(vulns)

        # Contract-level patterns
        # Pattern 5: Cross-function reentrancy (Medium)
        vulns = ReentrancyPatterns.detect_cross_function_reentrancy(
            contract, get_snippet
        )
        vulnerabilities.extend(vulns)

        return vulnerabilities

    def get_stats(self, result: Union[AnalysisResult, ScanResult]) -> Dict[str, Any]:
        """
        Get statistics from analysis results.

        Args:
            result: Analysis or scan result

        Returns:
            Dictionary with statistics including file count, contract count,
            vulnerability counts by severity, total vulnerabilities, and analysis time
        """
        if isinstance(result, AnalysisResult):
            return {
                'files': 1,
                'contracts': len(result.contracts),
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count,
                'total': len(result.vulnerabilities),
                'time_ms': result.analysis_time_ms
            }
        else:
            return {
                'files': result.files_scanned,
                'contracts': result.total_contracts,
                'critical': result.critical_count,
                'high': result.high_count,
                'medium': result.medium_count,
                'low': result.low_count,
                'total': len(result.all_vulnerabilities),
                'time_ms': result.total_analysis_time_ms
            }


# Convenience function for quick analysis
def analyze(source: str) -> List[Vulnerability]:
    """
    Quick analysis of Solidity source code.

    Args:
        source: Solidity source code or file path

    Returns:
        List of vulnerabilities found

    Raises:
        ValueError: If source is invalid
    """
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")

    detector = ReentrancyDetector()

    # Check if it's a file path
    source_path = Path(source)
    if source_path.exists() and source_path.suffix == '.sol':
        result = detector.analyze_file(source_path)
    else:
        result = detector.analyze_source(source)

    return result.vulnerabilities
