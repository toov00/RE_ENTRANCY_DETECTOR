"""
Vulnerability patterns and detection rules for reentrancy attacks.
"""

from typing import List, Optional, Callable
from .models import (
    Contract, Function, Vulnerability, VulnerabilityType,
    Severity, SourceLocation, CodeSnippet, ExternalCall, StateChange
)


class ReentrancyPatterns:
    """Detection rules for various reentrancy patterns."""

    # Remediation suggestions
    REMEDIATIONS = {
        VulnerabilityType.STATE_CHANGE_AFTER_CALL: (
            "Apply the Checks-Effects-Interactions pattern: "
            "1) Check conditions, 2) Update state variables, 3) Make external calls. "
            "Alternatively, use OpenZeppelin's ReentrancyGuard with the nonReentrant modifier."
        ),
        VulnerabilityType.EXTERNAL_CALL_IN_LOOP: (
            "Consider using the pull-over-push pattern where users withdraw funds themselves. "
            "If batch operations are necessary, limit the number of iterations and consider "
            "using OpenZeppelin's ReentrancyGuard."
        ),
        VulnerabilityType.MISSING_REENTRANCY_GUARD: (
            "Add OpenZeppelin's ReentrancyGuard and apply the nonReentrant modifier to this function. "
            "Install via: npm install @openzeppelin/contracts"
        ),
        VulnerabilityType.CROSS_FUNCTION_REENTRANCY: (
            "Apply the nonReentrant modifier to all functions that share state with functions "
            "making external calls. Consider using a mutex pattern that locks the entire contract."
        ),
        VulnerabilityType.DELEGATECALL_REENTRANCY: (
            "Be extremely cautious with delegatecall as it executes code in the context of the "
            "calling contract. Ensure the target is trusted and consider using a reentrancy guard."
        ),
    }

    # Reference links
    REFERENCES = {
        VulnerabilityType.STATE_CHANGE_AFTER_CALL: [
            "https://swcregistry.io/docs/SWC-107",
            "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
        ],
        VulnerabilityType.EXTERNAL_CALL_IN_LOOP: [
            "https://swcregistry.io/docs/SWC-113",
            "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/",
        ],
        VulnerabilityType.MISSING_REENTRANCY_GUARD: [
            "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
        ],
        VulnerabilityType.CROSS_FUNCTION_REENTRANCY: [
            "https://medium.com/coinmonks/protect-your-solidity-smart-contracts-from-reentrancy-attacks-9972c3af7c21",
        ],
    }

    @classmethod
    def detect_state_change_after_call(
        cls,
        function: Function,
        contract: Contract,
        get_snippet: Callable[[int, int], CodeSnippet]
    ) -> List[Vulnerability]:
        """
        Detect state changes that occur after external calls.
        This is the classic reentrancy vulnerability pattern.
        """
        vulnerabilities = []

        if not function.external_calls or not function.state_changes:
            return vulnerabilities

        for call in function.external_calls:
            # Find state changes that occur after this call
            for change in function.state_changes:
                if change.location.line > call.location.line:
                    # Found a state change after an external call
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.STATE_CHANGE_AFTER_CALL,
                        severity=Severity.CRITICAL,
                        title="State Change After External Call",
                        description=(
                            f"The function '{function.name}' modifies state variable "
                            f"'{change.variable}' (line {change.location.line}) after making "
                            f"an external {call.call_type} call (line {call.location.line}). "
                            f"An attacker can re-enter the function before the state update, "
                            f"potentially draining funds or manipulating contract state."
                        ),
                        location=call.location,
                        function_name=function.name,
                        contract_name=contract.name,
                        code_snippet=get_snippet(call.location.line, context=5),
                        external_call=call,
                        state_change=change,
                        remediation=cls.REMEDIATIONS[VulnerabilityType.STATE_CHANGE_AFTER_CALL],
                        references=cls.REFERENCES[VulnerabilityType.STATE_CHANGE_AFTER_CALL],
                        confidence="high"
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    @classmethod
    def detect_external_call_in_loop(
        cls,
        function: Function,
        contract: Contract,
        get_snippet: Callable[[int, int], CodeSnippet]
    ) -> List[Vulnerability]:
        """
        Detect external calls made inside loops.
        This can lead to gas exhaustion or reentrancy issues.
        """
        vulnerabilities = []

        for call in function.external_calls:
            if call.in_loop:
                vuln = Vulnerability(
                    vuln_type=VulnerabilityType.EXTERNAL_CALL_IN_LOOP,
                    severity=Severity.HIGH,
                    title="External Call in Loop",
                    description=(
                        f"The function '{function.name}' makes an external {call.call_type} "
                        f"call inside a loop (loop at line {call.loop_location.line if call.loop_location else 'unknown'}). "
                        f"This pattern is vulnerable to reentrancy attacks and can also "
                        f"lead to denial-of-service through gas exhaustion."
                    ),
                    location=call.location,
                    function_name=function.name,
                    contract_name=contract.name,
                    code_snippet=get_snippet(call.location.line, context=5),
                    external_call=call,
                    remediation=cls.REMEDIATIONS[VulnerabilityType.EXTERNAL_CALL_IN_LOOP],
                    references=cls.REFERENCES[VulnerabilityType.EXTERNAL_CALL_IN_LOOP],
                    confidence="high"
                )
                vulnerabilities.append(vuln)

        return vulnerabilities

    @classmethod
    def detect_missing_reentrancy_guard(
        cls,
        function: Function,
        contract: Contract,
        has_reentrancy_modifier: Callable[[Function], bool],
        get_snippet: Callable[[int, int], CodeSnippet]
    ) -> List[Vulnerability]:
        """
        Detect functions with external calls but no reentrancy protection.
        """
        vulnerabilities = []

        # Only check public/external functions that make external calls
        if function.visibility not in ['public', 'external']:
            return vulnerabilities

        if not function.external_calls:
            return vulnerabilities

        # Check if function has reentrancy guard
        if has_reentrancy_modifier(function):
            return vulnerabilities

        # Check for low-level calls which are most dangerous
        dangerous_calls = [c for c in function.external_calls
                          if c.call_type in ['call', 'delegatecall']]

        if dangerous_calls:
            call = dangerous_calls[0]
            vuln = Vulnerability(
                vuln_type=VulnerabilityType.MISSING_REENTRANCY_GUARD,
                severity=Severity.MEDIUM,
                title="Missing Reentrancy Guard",
                description=(
                    f"The function '{function.name}' makes external calls using "
                    f"'{call.call_type}' but does not have a reentrancy guard modifier. "
                    f"Consider adding the nonReentrant modifier from OpenZeppelin's "
                    f"ReentrancyGuard contract."
                ),
                location=function.location,
                function_name=function.name,
                contract_name=contract.name,
                code_snippet=get_snippet(function.location.line, context=3),
                external_call=call,
                remediation=cls.REMEDIATIONS[VulnerabilityType.MISSING_REENTRANCY_GUARD],
                references=cls.REFERENCES[VulnerabilityType.MISSING_REENTRANCY_GUARD],
                confidence="medium"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    @classmethod
    def detect_cross_function_reentrancy(
        cls,
        contract: Contract,
        get_snippet: Callable[[int, int], CodeSnippet]
    ) -> List[Vulnerability]:
        """
        Detect potential cross-function reentrancy vulnerabilities.
        This occurs when multiple functions share state and one makes external calls.
        """
        vulnerabilities = []

        # Find functions with external calls
        functions_with_calls = [
            f for f in contract.functions
            if f.external_calls and f.visibility in ['public', 'external']
        ]

        # Find functions that modify shared state
        for func_with_call in functions_with_calls:
            for other_func in contract.functions:
                if other_func.name == func_with_call.name:
                    continue

                if other_func.visibility not in ['public', 'external']:
                    continue

                # Check for shared state variables
                call_vars = set(s.variable for s in func_with_call.state_changes)
                other_vars = set(s.variable for s in other_func.state_changes)
                shared_vars = call_vars & other_vars

                if shared_vars:
                    call = func_with_call.external_calls[0]
                    vuln = Vulnerability(
                        vuln_type=VulnerabilityType.CROSS_FUNCTION_REENTRANCY,
                        severity=Severity.MEDIUM,
                        title="Cross-Function Reentrancy Risk",
                        description=(
                            f"Functions '{func_with_call.name}' and '{other_func.name}' "
                            f"both modify the same state variables ({', '.join(shared_vars)}). "
                            f"Since '{func_with_call.name}' makes external calls, an attacker "
                            f"could potentially re-enter through '{other_func.name}' to "
                            f"manipulate shared state."
                        ),
                        location=func_with_call.location,
                        function_name=func_with_call.name,
                        contract_name=contract.name,
                        code_snippet=get_snippet(func_with_call.location.line, context=3),
                        external_call=call,
                        remediation=cls.REMEDIATIONS[VulnerabilityType.CROSS_FUNCTION_REENTRANCY],
                        references=cls.REFERENCES[VulnerabilityType.CROSS_FUNCTION_REENTRANCY],
                        confidence="medium"
                    )
                    vulnerabilities.append(vuln)
                    break  # Only report once per function with calls

        return vulnerabilities

    @classmethod
    def detect_delegatecall_reentrancy(
        cls,
        function: Function,
        contract: Contract,
        get_snippet: Callable[[int, int], CodeSnippet]
    ) -> List[Vulnerability]:
        """
        Detect delegatecall usage which can lead to reentrancy in the caller's context.
        """
        vulnerabilities = []

        delegatecalls = [c for c in function.external_calls if c.call_type == 'delegatecall']

        for call in delegatecalls:
            vuln = Vulnerability(
                vuln_type=VulnerabilityType.DELEGATECALL_REENTRANCY,
                severity=Severity.HIGH,
                title="Delegatecall Reentrancy Risk",
                description=(
                    f"The function '{function.name}' uses delegatecall which executes "
                    f"external code in the context of this contract. If the target is "
                    f"malicious or compromised, it can modify this contract's state and "
                    f"potentially re-enter this or other functions."
                ),
                location=call.location,
                function_name=function.name,
                contract_name=contract.name,
                code_snippet=get_snippet(call.location.line, context=3),
                external_call=call,
                remediation=cls.REMEDIATIONS.get(
                    VulnerabilityType.DELEGATECALL_REENTRANCY,
                    "Exercise extreme caution with delegatecall."
                ),
                references=[],
                confidence="high"
            )
            vulnerabilities.append(vuln)

        return vulnerabilities
    