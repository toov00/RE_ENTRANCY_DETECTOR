// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * This contract contains multiple reentrancy vulnerabilities for testing purposes.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    mapping(address => bool) public hasDeposited;

    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        hasDeposited[msg.sender] = true;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * VULNERABLE: Classic reentrancy, state change after external call
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * VULNERABLE: Withdraw all funds
     */
    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // VULNERABILITY: Same pattern - call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0;
        totalDeposits -= amount;
    }

    /**
     * VULNERABLE: External calls in loop
     */
    function batchPayout(address[] calldata recipients, uint256[] calldata amounts) external {
        require(recipients.length == amounts.length, "Length mismatch");

        // VULNERABILITY: External calls inside a loop
        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: amounts[i]}("");
            require(success, "Transfer failed");
        }
    }

    /**
     * VULNERABLE: Using transfer in loop (less severe but still problematic)
     */
    function distributeRewards(address payable[] calldata winners) external {
        uint256 reward = address(this).balance / winners.length;

        // VULNERABILITY: External calls in loop
        for (uint256 i = 0; i < winners.length; i++) {
            winners[i].transfer(reward);
        }
    }

    /**
     * VULNERABLE: No reentrancy guard on function with external call
     */
    function emergencyWithdraw() external {
        uint256 amount = balances[msg.sender];

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        delete balances[msg.sender];
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}

/**
 * Demonstrates cross-function reentrancy
 */
contract CrossFunctionVulnerable {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;

    function claimRewards() external {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");

        (bool success, ) = msg.sender.call{value: reward}("");
        require(success, "Transfer failed");

        rewards[msg.sender] = 0;
    }

    /**
     * VULNERABLE: An attacker could re-enter through this function during claimRewards
     */
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function updateRewards() external {
        rewards[msg.sender] = balances[msg.sender] / 10;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}

/**
 * Demonstrates delegatecall reentrancy risks
 */
contract DelegateCallVulnerable {
    address public implementation;
    mapping(address => uint256) public balances;

    constructor(address _impl) {
        implementation = _impl;
    }

    /**
     * VULNERABLE: Delegatecall to untrusted address
     */
    function execute(bytes calldata data) external {
        // VULNERABILITY: delegatecall can modify this contract's state
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }
    
    function updateImplementation(address newImpl) external {
        implementation = newImpl;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
