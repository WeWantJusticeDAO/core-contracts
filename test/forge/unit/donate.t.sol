// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import 'forge-std/Test.sol';
import { Test } from 'forge-std/Test.sol';
import { ERC20 } from 'src/dependencies/openzeppelin/contracts/ERC20.sol';
import { IERC20 } from 'src/dependencies/openzeppelin/contracts/IERC20.sol';

import { ECDSA } from 'src/dependencies/openzeppelin/lib/ECDSA.sol';

import { ProxyAdmin } from 'src/dependencies/openzeppelin/upgradeability/ProxyAdmin.sol';
import { InitializableAdminUpgradeabilityProxy } from 'src/dependencies/openzeppelin/upgradeability/InitializableAdminUpgradeabilityProxy.sol';

import { Errors } from 'src/lib/Errors.sol';
import { ERC20Mock } from 'src/mocks/ERC20Mock.sol';

import { Donate } from 'src/Donate.sol';

contract DonateV2 is Donate {
    uint256 public constant version = 2;

    function getVersion() public pure returns (uint256) {
        return version;
    }
}

/**
 *Submitted for verification at Etherscan.io on 2021-07-09
 */

/// @title IProxy - Helper interface to access masterCopy of the Proxy on-chain
/// @author Richard Meissner - <richard@gnosis.io>
interface IProxy {
    function masterCopy() external view returns (address);
}

/// @title GnosisSafeProxy - Generic proxy contract allows to execute all transactions applying the code of a master contract.
/// @author Stefan George - <stefan@gnosis.io>
/// @author Richard Meissner - <richard@gnosis.io>
contract GnosisSafeProxy {
    // singleton always needs to be first declared variable, to ensure that it is at the same location in the contracts to which calls are delegated.
    // To reduce deployment costs this variable is internal and needs to be retrieved via `getStorageAt`
    address internal singleton;

    /// @dev Constructor function sets address of singleton contract.
    /// @param _singleton Singleton address.
    constructor(address _singleton) {
        require(_singleton != address(0), 'Invalid singleton address provided');
        singleton = _singleton;
    }

    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let _singleton := and(sload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            // 0xa619486e == keccak("masterCopy()"). The value is right padded to 32-bytes with 0s
            if eq(calldataload(0), 0xa619486e00000000000000000000000000000000000000000000000000000000) {
                mstore(0, _singleton)
                return(0, 0x20)
            }
            calldatacopy(0, 0, calldatasize())
            let success := delegatecall(gas(), _singleton, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if eq(success, 0) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
    }
}

contract TestDonate is Test {
    Donate public donate;
    ERC20Mock public tokenMock;
    ProxyAdmin public proxyAdmin;
    InitializableAdminUpgradeabilityProxy public proxy;

    GnosisSafeProxy public gnosisSafeProxy;

    bytes32 NAME = keccak256('ALEX');
    address public RECIPIENT = makeAddr('RECIPIENT');

    address public OWNER = makeAddr('OWNER');

    address public SIGNER = makeAddr('SIGNER');
    uint256 public SIGNER_PRIVATE_KEY = uint256(keccak256(abi.encodePacked('SIGNER')));

    address public USER = makeAddr('USER');
    uint256 public USER_PRIVATE_KEY = uint256(keccak256(abi.encodePacked('USER')));

    uint256 public DONATE_AMOUNT = 1000 ether;

    function test_donate_ERC20Token() public {
        bytes32 messageHash = getMessageHash(USER, address(tokenMock), DONATE_AMOUNT, RECIPIENT);

        _approveAndDonate(USER, address(tokenMock), DONATE_AMOUNT, SIGNER_PRIVATE_KEY, messageHash);

        assertEq(IERC20(tokenMock).balanceOf(address(RECIPIENT)), DONATE_AMOUNT);
    }

    function test_donate_ETH() public {
        bytes32 messageHash = getMessageHash(USER, address(0), DONATE_AMOUNT, RECIPIENT);

        hoax(USER, DONATE_AMOUNT);
        donate.donate{ value: DONATE_AMOUNT }(
            IERC20(address(0)),
            DONATE_AMOUNT,
            NAME,
            getSignature(messageHash, SIGNER_PRIVATE_KEY)
        );

        assertEq(address(RECIPIENT).balance, DONATE_AMOUNT);
    }

    function test_donate_invalidSignature() public {
        bytes32 messageHash = getMessageHash(USER, address(0), DONATE_AMOUNT, RECIPIENT);

        vm.expectRevert(bytes(Errors.INVALID_SIGNER));
        hoax(USER, DONATE_AMOUNT);
        donate.donate{ value: DONATE_AMOUNT }(
            IERC20(address(0)),
            DONATE_AMOUNT,
            NAME,
            getSignature(messageHash, USER_PRIVATE_KEY)
        );
    }

    function test_donateWrongAmount_ETH() public {
        bytes32 messageHash = getMessageHash(USER, address(0), DONATE_AMOUNT, RECIPIENT);

        vm.expectRevert(bytes('Wrong useage of ETH.universalTransferFrom()'));
        hoax(USER, DONATE_AMOUNT);
        donate.donate{ value: DONATE_AMOUNT - 1 }(
            IERC20(address(0)),
            DONATE_AMOUNT,
            NAME,
            getSignature(messageHash, SIGNER_PRIVATE_KEY)
        );
    }

    function test_recieve_revert() public {
        vm.expectRevert(bytes(Errors.RECEIVE_FALLBACK_PROHIBITED));
        hoax(USER, DONATE_AMOUNT);
        (bool success, ) = address(donate).call{ value: DONATE_AMOUNT }('');
        require(success);
    }

    function test_fallback_revert() public {
        vm.expectRevert(bytes(Errors.RECEIVE_FALLBACK_PROHIBITED));
        hoax(USER, DONATE_AMOUNT);
        (bool success, ) = address(donate).call{ value: DONATE_AMOUNT }(abi.encode(bytes('0x4')));
        require(success);
    }

    function _withdraw_ERC20Token() public {
        bytes32 messageHash = getMessageHash(USER, address(tokenMock), DONATE_AMOUNT, RECIPIENT);

        _approveAndDonate(USER, address(tokenMock), DONATE_AMOUNT, SIGNER_PRIVATE_KEY, messageHash);

        vm.prank(OWNER);
        donate.withdraw(IERC20(tokenMock), OWNER, DONATE_AMOUNT);

        assertEq(IERC20(tokenMock).balanceOf(address(donate)), 0);
        assertEq(IERC20(tokenMock).balanceOf(OWNER), DONATE_AMOUNT);
    }

    function _withdraw_ETH() public {
        bytes32 messageHash = getMessageHash(USER, address(0), DONATE_AMOUNT, RECIPIENT);

        hoax(USER, DONATE_AMOUNT);
        donate.donate{ value: DONATE_AMOUNT }(
            IERC20(address(0)),
            DONATE_AMOUNT,
            NAME,
            getSignature(messageHash, SIGNER_PRIVATE_KEY)
        );

        vm.prank(OWNER);
        donate.withdraw(IERC20(address(0)), OWNER, DONATE_AMOUNT);

        assertEq(address(donate).balance, 0);
        assertEq(address(OWNER).balance, DONATE_AMOUNT);
    }

    function _refund_ERC20Token() public {
        bytes32 messageHash = getMessageHash(USER, address(tokenMock), DONATE_AMOUNT, RECIPIENT);

        _approveAndDonate(USER, address(tokenMock), DONATE_AMOUNT, SIGNER_PRIVATE_KEY, messageHash);

        vm.prank(OWNER);
        donate.refund(IERC20(tokenMock), OWNER, DONATE_AMOUNT);

        assertEq(IERC20(tokenMock).balanceOf(address(donate)), 0);
        assertEq(IERC20(tokenMock).balanceOf(OWNER), DONATE_AMOUNT);
    }

    function _refund_ETH() public {
        bytes32 messageHash = getMessageHash(USER, address(0), DONATE_AMOUNT, RECIPIENT);

        hoax(USER, DONATE_AMOUNT);
        donate.donate{ value: DONATE_AMOUNT }(
            IERC20(address(0)),
            DONATE_AMOUNT,
            NAME,
            getSignature(messageHash, SIGNER_PRIVATE_KEY)
        );

        vm.prank(OWNER);
        donate.refund(IERC20(address(0)), OWNER, DONATE_AMOUNT);

        assertEq(address(donate).balance, 0);
        assertEq(address(OWNER).balance, DONATE_AMOUNT);
    }

    function test_setSigner_ERC20Token() public {
        bytes32 messageHash = getMessageHash(USER, address(tokenMock), DONATE_AMOUNT, RECIPIENT);

        address newSigner = makeAddr('NEW_SIGNER');
        uint256 newSignerPrivateKey = uint256(keccak256(abi.encodePacked('NEW_SIGNER')));

        vm.prank(OWNER);
        donate.setSigner(newSigner);

        _approveAndDonate(USER, address(tokenMock), DONATE_AMOUNT, newSignerPrivateKey, messageHash);

        assertEq(IERC20(tokenMock).balanceOf(address(donate)), 0);
        assertEq(IERC20(tokenMock).balanceOf(RECIPIENT), DONATE_AMOUNT);
    }

    function test_upgradePoxy_ETH() public {
        // donate ETH
        bytes32 messageHash = getMessageHash(USER, address(0), DONATE_AMOUNT, RECIPIENT);

        hoax(USER, DONATE_AMOUNT);
        donate.donate{ value: DONATE_AMOUNT }(
            IERC20(address(0)),
            DONATE_AMOUNT,
            NAME,
            getSignature(messageHash, SIGNER_PRIVATE_KEY)
        );

        // upgrade proxy
        DonateV2 donateV2 = new DonateV2();
        vm.prank(OWNER);
        proxyAdmin.upgrade(proxy, address(donateV2));

        donateV2 = DonateV2(payable(address(proxy)));

        assertEq(donateV2.getVersion(), 2);

        assertEq(address(donateV2).balance, 0);
        assertEq(address(RECIPIENT).balance, DONATE_AMOUNT);
    }

    function _approveAndDonate(
        address _from,
        address _token,
        uint256 _amount,
        uint256 _signer,
        bytes32 _messageHash
    ) public {
        vm.prank(_from);
        IERC20(_token).approve(address(donate), _amount);

        vm.prank(_from);
        donate.donate(IERC20(_token), _amount, NAME, getSignature(_messageHash, _signer));
    }

    function getSignature(bytes32 _hash, uint256 _privateKey) public pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, _hash);
        return abi.encodePacked(r, s, v);
    }

    function getMessageHash(
        address _from,
        address _token,
        uint256 _amount,
        address _recipient
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked('\x19Ethereum Signed Message:\n128', abi.encode(_from, _token, _amount, _recipient))
            );
    }

    function setUp() public {
        tokenMock = new ERC20Mock('Mock', 'MCK', USER, 1000000 ether);

        proxy = new InitializableAdminUpgradeabilityProxy();

        vm.prank(OWNER);
        proxyAdmin = new ProxyAdmin();

        Donate _donate = new Donate();
        proxy.initialize(
            address(_donate),
            address(proxyAdmin),
            abi.encodeWithSelector(_donate.initialize.selector, SIGNER, OWNER)
        );

        gnosisSafeProxy = new GnosisSafeProxy(0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552);
        RECIPIENT = address(gnosisSafeProxy);

        vm.prank(OWNER);
        Donate(payable(proxy)).setRecipient(RECIPIENT, NAME);

        donate = Donate(payable(address(proxy)));
    }
}
