"""
Solidity parser for extracting contract structure, functions, and calls.
Uses regex-based parsing for simplicity and portability.
"""

import re
from typing import List, Tuple, Optional, Dict, Callable
from .models import (
    Contract, Function, ExternalCall, StateChange,
    SourceLocation, CodeSnippet
)


class SolidityParser:
    """Parser for Solidity source code."""

    # Regex patterns for Solidity constructs
    PATTERNS = {
        # Contract/interface/library definition
        'contract': re.compile(
            r'(contract|interface|library|abstract\s+contract)\s+(\w+)(?:\s+is\s+([\w\s,]+))?\s*\{',
            re.MULTILINE
        ),

        # Function definition
        'function': re.compile(
            r'function\s+(\w+)\s*\(([^)]*)\)\s*((?:public|external|internal|private|view|pure|payable|virtual|override|\s|[\w\(\)]+)*)\s*(?:returns\s*\([^)]*\))?\s*\{',
            re.MULTILINE
        ),

        # State variable declaration
        'state_var': re.compile(
            r'^\s*(mapping\s*\([^;]+\)|[\w\[\]]+)\s+(public|private|internal|immutable|constant)?\s*(\w+)\s*[;=]',
            re.MULTILINE
        ),

        # External calls - call, delegatecall, staticcall
        'low_level_call': re.compile(
            r'(\w+(?:\.\w+)*)\s*\.\s*(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(',
            re.MULTILINE
        ),

        # Transfer and send
        'transfer_send': re.compile(
            r'(\w+(?:\.\w+)*)\s*\.\s*(transfer|send)\s*\(',
            re.MULTILINE
        ),

        # External contract calls (interface calls)
        'interface_call': re.compile(
            r'(\w+)\s*\(\s*(\w+(?:\.\w+)*)\s*\)\s*\.\s*(\w+)\s*\(',
            re.MULTILINE
        ),

        # State variable assignment
        'state_assignment': re.compile(
            r'(\w+(?:\[\s*[^\]]+\s*\])*)\s*(=|\+=|-=|\*=|\/=)\s*',
            re.MULTILINE
        ),

        # Delete statement
        'delete': re.compile(
            r'delete\s+(\w+(?:\[[^\]]+\])*)',
            re.MULTILINE
        ),

        # Increment/decrement
        'inc_dec': re.compile(
            r'(\w+(?:\[\s*[^\]]+\s*\])*)\s*(\+\+|--)',
            re.MULTILINE
        ),

        # Loop constructs
        'for_loop': re.compile(
            r'\bfor\s*\([^)]*\)\s*\{',
            re.MULTILINE
        ),
        'while_loop': re.compile(
            r'\bwhile\s*\([^)]*\)\s*\{',
            re.MULTILINE
        ),
        'do_while': re.compile(
            r'\bdo\s*\{',
            re.MULTILINE
        ),

        # Modifier usage
        'modifier': re.compile(
            r'\b(nonReentrant|noReentrant|reentrancyGuard|lock|mutex)\b',
            re.IGNORECASE
        ),

        # ReentrancyGuard import or inheritance
        'reentrancy_guard': re.compile(
            r'(ReentrancyGuard|ReentrancyGuardUpgradeable)',
            re.MULTILINE
        ),

        # Comments (to exclude from analysis)
        'single_comment': re.compile(r'//.*$', re.MULTILINE),
        'multi_comment': re.compile(r'/\*[\s\S]*?\*/', re.MULTILINE),

        # String literals (to exclude from analysis)
        'string_literal': re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\''),
    }

    def __init__(self):
        self.source_code: str = ""
        self.lines: List[str] = []
        self.cleaned_code: str = ""

    def parse(self, source_code: str) -> List[Contract]:
        """
        Parse Solidity source code and return list of contracts.
        
        Args:
            source_code: Solidity source code string
            
        Returns:
            List of parsed Contract objects
            
        Raises:
            ValueError: If source_code is invalid
        """
        if not isinstance(source_code, str):
            raise ValueError("source_code must be a string")
        
        self.source_code = source_code
        self.lines = source_code.split('\n')

        # Remove comments and strings for pattern matching
        self.cleaned_code = self._remove_comments_and_strings(source_code)

        contracts = []
        for match in self.PATTERNS['contract'].finditer(self.cleaned_code):
            contract = self._parse_contract(match)
            if contract:
                contracts.append(contract)

        return contracts

    def _remove_comments_and_strings(self, code: str) -> str:
        """Remove comments and string literals from code, preserving line structure."""
        # Remove multi-line comments first, replacing with spaces to preserve line structure
        def replace_multiline(match):
            # Replace with spaces equal to the number of newlines in the comment
            content = match.group(0)
            newline_count = content.count('\n')
            return ' ' * (len(content) - newline_count) + '\n' * newline_count
        
        code = self.PATTERNS['multi_comment'].sub(replace_multiline, code)
        # Remove single-line comments (preserve the newline if comment is at end of line)
        code = self.PATTERNS['single_comment'].sub('', code)
        # Replace string literals with placeholders to preserve positions
        code = self.PATTERNS['string_literal'].sub('""', code)
        return code

    def _get_line_number(self, pos: int, code: Optional[str] = None) -> int:
        """Get line number for a character position."""
        if code is None:
            code = self.source_code
        return code[:pos].count('\n') + 1
    
    def _get_line_number_from_cleaned(self, pos: int) -> int:
        """Get line number for a position in cleaned_code, mapping back to source_code."""
        # Since newlines are preserved when removing comments, we can count newlines
        # in cleaned_code up to the position, which gives us the correct line number
        return self.cleaned_code[:pos].count('\n') + 1

    def _find_matching_brace(self, code: str, start: int) -> int:
        """Find the position of the matching closing brace."""
        depth = 1
        pos = start
        while pos < len(code) and depth > 0:
            if code[pos] == '{':
                depth += 1
            elif code[pos] == '}':
                depth -= 1
            pos += 1
        return pos - 1 if depth == 0 else -1

    def _parse_contract(self, match: re.Match) -> Optional[Contract]:
        """Parse a contract definition."""
        contract_type = match.group(1)
        name = match.group(2)
        inherits_str = match.group(3)

        start_pos = match.end() - 1  # Position of opening brace
        end_pos = self._find_matching_brace(self.cleaned_code, start_pos + 1)

        if end_pos == -1:
            return None

        contract_body = self.cleaned_code[start_pos:end_pos + 1]
        body_offset = start_pos

        # Parse inheritance
        inherits = []
        if inherits_str:
            inherits = [s.strip() for s in inherits_str.split(',')]

        # Check for reentrancy guard
        has_guard = bool(self.PATTERNS['reentrancy_guard'].search(self.source_code))

        contract = Contract(
            name=name,
            location=SourceLocation(
                line=self._get_line_number(match.start()),
                end_line=self._get_line_number(end_pos)
            ),
            inherits=inherits,
            has_reentrancy_guard=has_guard
        )

        # Parse state variables
        contract.state_variables = self._parse_state_variables(contract_body)

        # Parse functions
        contract.functions = self._parse_functions(contract_body, body_offset, contract.state_variables)

        return contract

    def _parse_state_variables(self, contract_body: str) -> List[str]:
        """Extract state variable names from contract body."""
        variables = []
        for match in self.PATTERNS['state_var'].finditer(contract_body):
            var_name = match.group(3)
            if var_name:
                variables.append(var_name)

        # Also look for mapping declarations
        mapping_pattern = re.compile(r'mapping\s*\([^)]+\)\s*(?:public|private|internal)?\s*(\w+)')
        for match in mapping_pattern.finditer(contract_body):
            var_name = match.group(1)
            if var_name and var_name not in variables:
                variables.append(var_name)

        return variables

    def _parse_functions(self, contract_body: str, offset: int, state_vars: List[str]) -> List[Function]:
        """Parse all functions in a contract."""
        functions = []

        for match in self.PATTERNS['function'].finditer(contract_body):
            func = self._parse_function(match, contract_body, offset, state_vars)
            if func:
                functions.append(func)

        return functions

    def _parse_function(self, match: re.Match, contract_body: str, offset: int, state_vars: List[str]) -> Optional[Function]:
        """Parse a single function."""
        name = match.group(1)
        params = match.group(2)
        modifiers_str = match.group(3) or ""

        # Find function body
        body_start = match.end() - 1  # Opening brace
        body_end = self._find_matching_brace(contract_body, body_start + 1)

        if body_end == -1:
            return None

        function_body = contract_body[body_start:body_end + 1]

        # Parse visibility
        visibility = 'internal'  # Default
        for vis in ['public', 'external', 'internal', 'private']:
            if vis in modifiers_str:
                visibility = vis
                break

        # Parse modifiers
        modifiers = self._extract_modifiers(modifiers_str)

        # Check for payable
        is_payable = 'payable' in modifiers_str

        # Get absolute line numbers (using cleaned_code positions)
        func_start_line = self._get_line_number_from_cleaned(offset + match.start())
        body_start_line = self._get_line_number_from_cleaned(offset + body_start)
        body_end_line = self._get_line_number_from_cleaned(offset + body_end)

        func = Function(
            name=name,
            location=SourceLocation(
                line=func_start_line,
                end_line=body_end_line
            ),
            visibility=visibility,
            modifiers=modifiers,
            is_payable=is_payable,
            body_start_line=body_start_line,
            body_end_line=body_end_line
        )

        # Parse external calls in function body
        func.external_calls = self._parse_external_calls(function_body, offset + body_start)

        # Parse state changes
        func.state_changes = self._parse_state_changes(function_body, offset + body_start, state_vars)

        return func

    def _extract_modifiers(self, modifiers_str: str) -> List[str]:
        """Extract modifier names from modifier string."""
        # Common keywords that are not modifiers
        keywords = {'public', 'external', 'internal', 'private', 'view', 'pure',
                    'payable', 'virtual', 'override', 'returns'}

        modifiers = []
        # Match modifier calls like nonReentrant or onlyOwner()
        modifier_pattern = re.compile(r'\b(\w+)(?:\([^)]*\))?')
        for match in modifier_pattern.finditer(modifiers_str):
            mod_name = match.group(1)
            if mod_name not in keywords:
                modifiers.append(mod_name)

        return modifiers

    def _parse_external_calls(self, function_body: str, offset: int) -> List[ExternalCall]:
        """Find all external calls in a function body."""
        calls = []

        # Find loops first to mark calls that are inside them
        loops = self._find_loops(function_body)

        # Low-level calls (call, delegatecall, staticcall)
        for match in self.PATTERNS['low_level_call'].finditer(function_body):
            # Calculate line number from cleaned_code position
            line = self._get_line_number_from_cleaned(offset + match.start())
            call = ExternalCall(
                location=SourceLocation(line=line),
                call_type=match.group(2),
                target=match.group(1),
                code=self._get_line_content(line),
                in_loop=self._is_in_loop(match.start(), loops),
                loop_location=self._get_loop_location(match.start(), loops, offset)
            )
            calls.append(call)

        # Transfer and send
        for match in self.PATTERNS['transfer_send'].finditer(function_body):
            # Calculate line number from cleaned_code position
            line = self._get_line_number_from_cleaned(offset + match.start())
            call = ExternalCall(
                location=SourceLocation(line=line),
                call_type=match.group(2),
                target=match.group(1),
                code=self._get_line_content(line),
                in_loop=self._is_in_loop(match.start(), loops),
                loop_location=self._get_loop_location(match.start(), loops, offset)
            )
            calls.append(call)

        return calls

    def _find_loops(self, function_body: str) -> List[Tuple[int, int]]:
        """Find all loop constructs and their ranges."""
        loops = []

        for pattern_name in ['for_loop', 'while_loop', 'do_while']:
            for match in self.PATTERNS[pattern_name].finditer(function_body):
                start = match.start()
                # Find the matching closing brace
                brace_start = function_body.find('{', match.end() - 1)
                if brace_start != -1:
                    end = self._find_matching_brace(function_body, brace_start + 1)
                    if end != -1:
                        loops.append((start, end))

        return loops

    def _is_in_loop(self, pos: int, loops: List[Tuple[int, int]]) -> bool:
        """Check if a position is inside any loop."""
        for loop_start, loop_end in loops:
            if loop_start <= pos <= loop_end:
                return True
        return False

    def _get_loop_location(self, pos: int, loops: List[Tuple[int, int]], offset: int) -> Optional[SourceLocation]:
        """Get the location of the loop containing a position."""
        for loop_start, loop_end in loops:
            if loop_start <= pos <= loop_end:
                return SourceLocation(line=self._get_line_number_from_cleaned(offset + loop_start))
        return None

    def _parse_state_changes(self, function_body: str, offset: int, state_vars: List[str]) -> List[StateChange]:
        """Find all state variable modifications in a function body."""
        changes = []

        # Assignment operations
        for match in self.PATTERNS['state_assignment'].finditer(function_body):
            var_name = match.group(1).split('[')[0]  # Get base variable name
            if var_name in state_vars:
                line = self._get_line_number_from_cleaned(offset + match.start())
                changes.append(StateChange(
                    location=SourceLocation(line=line),
                    variable=var_name,
                    code=self._get_line_content(line),
                    change_type='assignment'
                ))

        # Delete operations
        for match in self.PATTERNS['delete'].finditer(function_body):
            var_name = match.group(1).split('[')[0]
            if var_name in state_vars:
                line = self._get_line_number_from_cleaned(offset + match.start())
                changes.append(StateChange(
                    location=SourceLocation(line=line),
                    variable=var_name,
                    code=self._get_line_content(line),
                    change_type='delete'
                ))

        # Increment/decrement
        for match in self.PATTERNS['inc_dec'].finditer(function_body):
            var_name = match.group(1).split('[')[0]
            if var_name in state_vars:
                line = self._get_line_number_from_cleaned(offset + match.start())
                changes.append(StateChange(
                    location=SourceLocation(line=line),
                    variable=var_name,
                    code=self._get_line_content(line),
                    change_type='increment' if '++' in match.group(2) else 'decrement'
                ))

        return changes

    def _get_line_content(self, line_number: int) -> str:
        """
        Get the content of a specific line.
        
        Args:
            line_number: 1-based line number
            
        Returns:
            Stripped line content, or empty string if line number is invalid
        """
        if not isinstance(line_number, int) or line_number < 1:
            return ""
        if line_number > len(self.lines):
            return ""
        return self.lines[line_number - 1].strip()

    def get_code_snippet(self, line: int, context: int = 3) -> CodeSnippet:
        """
        Get a code snippet around a specific line.
        
        Args:
            line: Line number to center the snippet on
            context: Number of lines before and after to include
            
        Returns:
            CodeSnippet object with code and metadata
        """
        if not isinstance(line, int) or line < 1:
            line = 1
        if not isinstance(context, int) or context < 0:
            context = 3
            
        start = max(1, line - context)
        end = min(len(self.lines), line + context)

        snippet_lines = self.lines[start - 1:end]
        return CodeSnippet(
            code='\n'.join(snippet_lines),
            start_line=start,
            highlight_lines=[line] if 1 <= line <= len(self.lines) else []
        )

    def has_reentrancy_modifier(self, function: Function) -> bool:
        """
        Check if a function has a reentrancy guard modifier.
        
        Args:
            function: Function to check
            
        Returns:
            True if function has a reentrancy guard modifier, False otherwise
        """
        if not isinstance(function, Function):
            return False
            
        guard_modifiers = ['nonreentrant', 'noreentrant', 'reentrancyguard', 'lock', 'mutex']
        for mod in function.modifiers:
            if isinstance(mod, str) and mod.lower() in guard_modifiers:
                return True
        return False
    