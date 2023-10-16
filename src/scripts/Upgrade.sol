// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import 'forge-std/Script.sol';

import { Donate } from '../Donate.sol';
import { ProxyAdmin } from '../dependencies/openzeppelin/upgradeability/ProxyAdmin.sol';
import { InitializableAdminUpgradeabilityProxy } from '../dependencies/openzeppelin/upgradeability/InitializableAdminUpgradeabilityProxy.sol';

contract Upgrade is Script {
    InitializableAdminUpgradeabilityProxy proxy =
        InitializableAdminUpgradeabilityProxy(payable(0x000000c6a7c2141afc9c084eB1162972f4C25949));

    ProxyAdmin proxyAdmin = ProxyAdmin(0x4986d7BEe120DF657fcA29cc11BF0B04836118a2);

    bytes32 ALEX = keccak256('ALEX');
    bytes32 ROMAN = keccak256('ROMAN');
    bytes32 GLOBAL = keccak256('GLOBAL');

    address signer = 0x111111f657d61c800B6BE4CD3b30C185EF066C8F;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint('PRIVATE_KEY');
        vm.startBroadcast(deployerPrivateKey);

        Donate impl = new Donate();
        proxyAdmin.upgrade(proxy, address(impl));

        vm.stopBroadcast();
    }
}
