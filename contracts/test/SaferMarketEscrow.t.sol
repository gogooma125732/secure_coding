// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SaferMarketEscrow} from "../src/SaferMarketEscrow.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function startPrank(address sender) external;
    function stopPrank() external;
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 selector) external;
    function expectPartialRevert(bytes4 selector) external;
}

contract MockPaymentToken is ERC20 {
    constructor() ERC20("SAFER Test KRW", "tKRW") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract FeeOnTransferToken is ERC20 {
    constructor() ERC20("Fee Token", "FEE") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && value >= 100) {
            uint256 fee = value / 100;
            super._update(from, address(0), fee);
            super._update(from, to, value - fee);
        } else {
            super._update(from, to, value);
        }
    }
}

contract SaferMarketEscrowTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 private constant SELLER_KEY = 0xA11CE;
    uint256 private constant BUYER_KEY = 0xB0B;
    uint256 private constant ATTACKER_KEY = 0xBAD;
    uint256 private constant AMOUNT = 8_000 * 1e6;

    MockPaymentToken private token;
    SaferMarketEscrow private escrow;
    address private seller;
    address private buyer;
    address private attacker;

    function setUp() public {
        seller = vm.addr(SELLER_KEY);
        buyer = vm.addr(BUYER_KEY);
        attacker = vm.addr(ATTACKER_KEY);
        token = new MockPaymentToken();
        escrow = new SaferMarketEscrow(address(this), address(this), IERC20(address(token)), block.chainid);
        token.mint(buyer, AMOUNT * 10);
        vm.prank(buyer);
        token.approve(address(escrow), type(uint256).max);
    }

    function testFixedSignedPriceFundsAndReleasesExactlyOnce() public {
        SaferMarketEscrow.Order memory order = _order(bytes32("order-1"), 1);
        bytes memory signature = _sign(order, escrow);

        vm.prank(buyer);
        escrow.fund(order, signature);
        _assertEq(token.balanceOf(address(escrow)), AMOUNT, "escrow amount");
        _assertEq(escrow.totalLiability(), AMOUNT, "liability");

        vm.prank(seller);
        escrow.markShipped(order.orderId);
        vm.prank(buyer);
        escrow.confirmReceipt(order.orderId);

        _assertEq(token.balanceOf(seller), AMOUNT, "seller settlement");
        _assertEq(escrow.totalLiability(), 0, "cleared liability");
        _assertEq(uint256(escrow.escrow(order.orderId).state), uint256(SaferMarketEscrow.State.Released), "state");
    }

    function testReplayOfOrderIdIsRejected() public {
        SaferMarketEscrow.Order memory order = _order(bytes32("order-2"), 2);
        bytes memory signature = _sign(order, escrow);
        vm.prank(buyer);
        escrow.fund(order, signature);

        vm.prank(buyer);
        vm.expectRevert(SaferMarketEscrow.OrderAlreadyUsed.selector);
        escrow.fund(order, signature);
    }

    function testSellerNonceCannotAuthorizeAnotherOrder() public {
        SaferMarketEscrow.Order memory first = _order(bytes32("order-3"), 3);
        bytes memory firstSignature = _sign(first, escrow);
        vm.prank(buyer);
        escrow.fund(first, firstSignature);

        SaferMarketEscrow.Order memory second = _order(bytes32("order-4"), 3);
        bytes memory secondSignature = _sign(second, escrow);
        vm.prank(buyer);
        vm.expectRevert(SaferMarketEscrow.SellerNonceAlreadyUsed.selector);
        escrow.fund(second, secondSignature);
    }

    function testExpiredSignatureIsRejected() public {
        SaferMarketEscrow.Order memory order = _order(bytes32("order-5"), 5);
        bytes memory signature = _sign(order, escrow);
        vm.warp(order.signatureDeadline + 1);

        vm.prank(buyer);
        vm.expectRevert(SaferMarketEscrow.InvalidDeadline.selector);
        escrow.fund(order, signature);
    }

    function testFrontRunnerCannotReplaceBoundBuyer() public {
        SaferMarketEscrow.Order memory order = _order(bytes32("order-6"), 6);
        bytes memory signature = _sign(order, escrow);
        vm.prank(attacker);
        vm.expectRevert(SaferMarketEscrow.BuyerMismatch.selector);
        escrow.fund(order, signature);
    }

    function testTamperedAmountBreaksSellerSignature() public {
        SaferMarketEscrow.Order memory signedOrder = _order(bytes32("order-7"), 7);
        bytes memory signature = _sign(signedOrder, escrow);
        signedOrder.amount = 1;

        vm.prank(buyer);
        vm.expectRevert(SaferMarketEscrow.InvalidSellerSignature.selector);
        escrow.fund(signedOrder, signature);
    }

    function testFeeOnTransferTokenIsRejectedInsteadOfMisaccounted() public {
        FeeOnTransferToken feeToken = new FeeOnTransferToken();
        SaferMarketEscrow feeEscrow =
            new SaferMarketEscrow(address(this), address(this), IERC20(address(feeToken)), block.chainid);
        feeToken.mint(buyer, AMOUNT * 2);
        vm.prank(buyer);
        feeToken.approve(address(feeEscrow), type(uint256).max);
        SaferMarketEscrow.Order memory order = _orderFor(bytes32("order-8"), 8, address(feeToken));
        bytes memory signature = _sign(order, feeEscrow);

        vm.prank(buyer);
        vm.expectRevert(SaferMarketEscrow.UnsupportedTransferBehavior.selector);
        feeEscrow.fund(order, signature);
        _assertEq(feeEscrow.totalLiability(), 0, "reverted liability");
    }

    function testBuyerCanRecoverFundsWhenSellerMissesDeadline() public {
        SaferMarketEscrow.Order memory order = _order(bytes32("order-9"), 9);
        bytes memory signature = _sign(order, escrow);
        vm.prank(buyer);
        escrow.fund(order, signature);
        vm.warp(order.fulfillmentDeadline + 1);

        uint256 beforeBalance = token.balanceOf(buyer);
        vm.prank(buyer);
        escrow.claimExpiredRefund(order.orderId);
        _assertEq(token.balanceOf(buyer), beforeBalance + AMOUNT, "buyer refund");
    }

    function testOnlyArbiterCanResolveDispute() public {
        SaferMarketEscrow.Order memory order = _order(bytes32("order-10"), 10);
        bytes memory signature = _sign(order, escrow);
        vm.prank(buyer);
        escrow.fund(order, signature);
        vm.prank(seller);
        escrow.markShipped(order.orderId);
        vm.prank(buyer);
        escrow.openDispute(order.orderId);

        vm.prank(attacker);
        vm.expectPartialRevert(bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")));
        escrow.resolveDispute(order.orderId, false);

        escrow.resolveDispute(order.orderId, false);
        _assertEq(uint256(escrow.escrow(order.orderId).state), uint256(SaferMarketEscrow.State.Refunded), "state");
    }

    function testPauseBlocksNewFundingButDoesNotTrapExistingBuyerFunds() public {
        SaferMarketEscrow.Order memory funded = _order(bytes32("order-11"), 11);
        bytes memory fundedSignature = _sign(funded, escrow);
        vm.prank(buyer);
        escrow.fund(funded, fundedSignature);
        escrow.pause();

        SaferMarketEscrow.Order memory blocked = _order(bytes32("order-12"), 12);
        bytes memory blockedSignature = _sign(blocked, escrow);
        vm.prank(buyer);
        vm.expectPartialRevert(bytes4(keccak256("EnforcedPause()")));
        escrow.fund(blocked, blockedSignature);

        vm.warp(funded.fulfillmentDeadline + 1);
        vm.prank(buyer);
        escrow.claimExpiredRefund(funded.orderId);
        _assertEq(uint256(escrow.escrow(funded.orderId).state), uint256(SaferMarketEscrow.State.Refunded), "exit while paused");
    }

    function _order(bytes32 orderId, uint256 nonce) private view returns (SaferMarketEscrow.Order memory) {
        return _orderFor(orderId, nonce, address(token));
    }

    function _orderFor(bytes32 orderId, uint256 nonce, address paymentToken)
        private
        view
        returns (SaferMarketEscrow.Order memory)
    {
        return SaferMarketEscrow.Order({
            orderId: orderId,
            listingId: keccak256(abi.encodePacked("listing", orderId)),
            buyer: buyer,
            seller: seller,
            token: paymentToken,
            amount: AMOUNT,
            sellerNonce: nonce,
            signatureDeadline: uint64(block.timestamp + 1 hours),
            fulfillmentDeadline: uint64(block.timestamp + 7 days)
        });
    }

    function _sign(SaferMarketEscrow.Order memory order, SaferMarketEscrow target)
        private
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SELLER_KEY, target.hashOrder(order));
        return abi.encodePacked(r, s, v);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory message) private pure {
        require(actual == expected, message);
    }
}
