# Re-entrancy Detector

A static analysis tool that scans Solidity smart contracts for re-entrancy vulnerabilities.

## What It Does

Scans Solidity contracts to identify re-entrancy attack vectors. Detects state changes after external calls, calls within loops, missing guards, and cross-function vulnerabilities.

**Features:**
- Detects 5+ re-entrancy patterns (classic, loops, delegatecall, guards, cross-function)
- Multiple output formats (text, JSON, Markdown)
- Detailed reports with severity levels and remediation suggestions
- VS Code extension for real-time analysis

## Installation

**Requirements:** Python 3.8+

```bash
git clone https://github.com/toov00/reentrancy-detector.git
cd reentrancy-detector
pip install -e .
```

Optional dependencies:
- `pytest`: for running tests

## Usage

### Quick Start

```bash
# Scan a single file
python -m src.cli scan contract.sol

# Scan a directory
python -m src.cli scan ./contracts/
```

### Command Options

```bash
# JSON output
python -m src.cli scan contract.sol --format json -o report.json

# Markdown output
python -m src.cli scan contract.sol --format markdown -o report.md

# Verbose mode (shows code snippets)
python -m src.cli scan contract.sol --verbose
```

```bash
# Severity filtering
python -m src.cli scan contract.sol --severity high

# Exclude patterns from directory scans
python -m src.cli scan ./contracts/ --exclude test mock

# Quiet mode (only vulnerabilities, no summary)
python -m src.cli scan contract.sol --quiet

# Disable colored output
python -m src.cli scan contract.sol --no-color
```

Available severity levels: `critical`, `high`, `medium`, `low`, `info`

## Example Output

```
[CRITICAL] State Change After External Call
├── Contract: VulnerableBank
├── Function: withdraw()
├── Line: 25
└── Remediation: Apply Checks-Effects-Interactions pattern

Summary: 2 Critical, 1 High, 0 Medium, 0 Low
```

## Detection Patterns

1. **State Change After Call** (Critical): State modified after external call
2. **External Call in Loop** (High): `.call()` invoked inside for/while loops
3. **Delegatecall Usage** (High): Executes foreign code in contract context
4. **Missing Reentrancy Guard** (Medium): Absence of `nonReentrant` modifier
5. **Cross-Function Reentrancy** (Medium): Shared state across functions

## Examples

See `examples/` directory for sample contracts:
- `vulnerable_bank.sol`: Classic re-entrancy vulnerability
- `safe_bank.sol`: Secure implementation using checks-effects-interactions pattern
- `cross_function.sol`: Cross-function re-entrancy example

## VS Code Extension

A VS Code extension is available in the `vscode-extension/` directory. See `vscode-extension/README.md` for installation instructions.

Provides real-time analysis, inline diagnostics, and workspace-wide scanning.

## Troubleshooting

**Import errors?** Make sure you're running from project root and `src/` is in your path.

**No vulnerabilities found?** Try lowering the severity threshold or use `--verbose` to see detailed output.

**Extension not working?** Verify Python 3.8+ is installed and the analyzer package is installed: `pip install -e .`

## Contributing

Contributions welcome! To add new detection patterns:
1. Add pattern logic to `src/patterns.py`
2. Update detection rules in `src/detector.py`
3. Test against example contracts

## License

MIT License

## Resources

- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)
- [Consensys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/)
- [OpenZeppelin ReentrancyGuard](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard)
