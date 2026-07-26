// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @title SAFER Market fixed-price escrow
/// @notice Holds one allowlisted ERC-20 for physical-goods trades. Listing data,
///         chat, shipping PII, and moderation remain off-chain.
/// @dev The signed amount is the price. This contract deliberately does not read
///      a spot-price oracle, eliminating oracle manipulation from settlement.
contract SaferMarketEscrow is EIP712, AccessControlDefaultAdminRules, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant ARBITER_ROLE = keccak256("ARBITER_ROLE");
    uint48 public constant ADMIN_TRANSFER_DELAY = 2 days;
    uint64 public constant MAX_FULFILLMENT_WINDOW = 30 days;
    bytes32 public constant ORDER_TYPEHASH = keccak256(
        "Order(bytes32 orderId,bytes32 listingId,address buyer,address seller,address token,uint256 amount,uint256 sellerNonce,uint64 signatureDeadline,uint64 fulfillmentDeadline)"
    );

    enum State {
        None,
        Funded,
        Shipped,
        Disputed,
        Released,
        Refunded
    }

    struct Order {
        bytes32 orderId;
        bytes32 listingId;
        address buyer;
        address seller;
        address token;
        uint256 amount;
        uint256 sellerNonce;
        uint64 signatureDeadline;
        uint64 fulfillmentDeadline;
    }

    struct Escrow {
        address buyer;
        address seller;
        uint256 amount;
        uint64 fundedAt;
        uint64 fulfillmentDeadline;
        State state;
    }

    error ZeroAddress();
    error WrongChain(uint256 expected, uint256 actual);
    error InvalidParticipant();
    error InvalidAmount();
    error InvalidDeadline();
    error UnsupportedToken();
    error BuyerMismatch();
    error InvalidSellerSignature();
    error OrderAlreadyUsed();
    error SellerNonceAlreadyUsed();
    error InvalidState(State expected, State actual);
    error UnauthorizedParticipant();
    error FulfillmentWindowOpen();
    error FulfillmentWindowClosed();
    error UnsupportedTransferBehavior();
    error InsufficientExcessBalance();

    event EscrowFunded(
        bytes32 indexed orderId,
        bytes32 indexed listingId,
        address indexed buyer,
        address seller,
        address token,
        uint256 amount,
        uint64 fulfillmentDeadline
    );
    event ShipmentMarked(bytes32 indexed orderId, address indexed seller);
    event DisputeOpened(bytes32 indexed orderId, address indexed openedBy);
    event EscrowReleased(bytes32 indexed orderId, address indexed seller, uint256 amount);
    event EscrowRefunded(bytes32 indexed orderId, address indexed buyer, uint256 amount);
    event ExcessTokenRecovered(address indexed token, address indexed recipient, uint256 amount);

    IERC20 public immutable paymentToken;
    uint256 public immutable deploymentChainId;
    uint256 public totalLiability;

    mapping(bytes32 orderId => Escrow escrow) private _escrows;
    mapping(address seller => mapping(uint256 nonce => bool used)) public sellerNonceUsed;

    constructor(address admin, address arbiter, IERC20 token, uint256 expectedChainId)
        EIP712("SAFER Market Escrow", "1")
        AccessControlDefaultAdminRules(ADMIN_TRANSFER_DELAY, admin)
    {
        if (admin == address(0) || arbiter == address(0) || address(token) == address(0)) revert ZeroAddress();
        if (address(token).code.length == 0) revert UnsupportedToken();
        if (block.chainid != expectedChainId) revert WrongChain(expectedChainId, block.chainid);
        paymentToken = token;
        deploymentChainId = expectedChainId;
        _grantRole(ARBITER_ROLE, arbiter);
    }

    function hashOrder(Order calldata order) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    ORDER_TYPEHASH,
                    order.orderId,
                    order.listingId,
                    order.buyer,
                    order.seller,
                    order.token,
                    order.amount,
                    order.sellerNonce,
                    order.signatureDeadline,
                    order.fulfillmentDeadline
                )
            )
        );
    }

    function escrow(bytes32 orderId) external view returns (Escrow memory) {
        return _escrows[orderId];
    }

    function fund(Order calldata order, bytes calldata sellerSignature) external nonReentrant whenNotPaused {
        if (msg.sender != order.buyer) revert BuyerMismatch();
        if (order.buyer == address(0) || order.seller == address(0)) revert ZeroAddress();
        if (order.buyer == order.seller) revert InvalidParticipant();
        if (order.token != address(paymentToken)) revert UnsupportedToken();
        if (order.amount == 0) revert InvalidAmount();
        if (block.timestamp > order.signatureDeadline) revert InvalidDeadline();
        if (
            order.fulfillmentDeadline <= order.signatureDeadline
                || order.fulfillmentDeadline > block.timestamp + MAX_FULFILLMENT_WINDOW
        ) revert InvalidDeadline();
        if (_escrows[order.orderId].state != State.None) revert OrderAlreadyUsed();
        if (sellerNonceUsed[order.seller][order.sellerNonce]) revert SellerNonceAlreadyUsed();
        if (!SignatureChecker.isValidSignatureNow(order.seller, hashOrder(order), sellerSignature)) {
            revert InvalidSellerSignature();
        }

        // Checks-effects-interactions: consume both replay guards before touching the token.
        sellerNonceUsed[order.seller][order.sellerNonce] = true;
        _escrows[order.orderId] = Escrow({
            buyer: order.buyer,
            seller: order.seller,
            amount: order.amount,
            fundedAt: uint64(block.timestamp),
            fulfillmentDeadline: order.fulfillmentDeadline,
            state: State.Funded
        });
        totalLiability += order.amount;

        uint256 beforeBalance = paymentToken.balanceOf(address(this));
        paymentToken.safeTransferFrom(order.buyer, address(this), order.amount);
        uint256 received = paymentToken.balanceOf(address(this)) - beforeBalance;
        if (received != order.amount) revert UnsupportedTransferBehavior();

        emit EscrowFunded(
            order.orderId,
            order.listingId,
            order.buyer,
            order.seller,
            order.token,
            order.amount,
            order.fulfillmentDeadline
        );
    }

    function markShipped(bytes32 orderId) external whenNotPaused {
        Escrow storage item = _requireState(orderId, State.Funded);
        if (msg.sender != item.seller) revert UnauthorizedParticipant();
        if (block.timestamp > item.fulfillmentDeadline) revert FulfillmentWindowClosed();
        item.state = State.Shipped;
        emit ShipmentMarked(orderId, msg.sender);
    }

    /// @dev Pausing blocks new exposure but never blocks an already-funded exit.
    function confirmReceipt(bytes32 orderId) external nonReentrant {
        Escrow storage item = _requireState(orderId, State.Shipped);
        if (msg.sender != item.buyer) revert UnauthorizedParticipant();
        _release(orderId, item);
    }

    function openDispute(bytes32 orderId) external {
        Escrow storage item = _requireState(orderId, State.Shipped);
        if (msg.sender != item.buyer && msg.sender != item.seller) revert UnauthorizedParticipant();
        item.state = State.Disputed;
        emit DisputeOpened(orderId, msg.sender);
    }

    function refundBySeller(bytes32 orderId) external nonReentrant {
        Escrow storage item = _escrows[orderId];
        if (item.state != State.Funded && item.state != State.Shipped) {
            revert InvalidState(State.Funded, item.state);
        }
        if (msg.sender != item.seller) revert UnauthorizedParticipant();
        _refund(orderId, item);
    }

    function claimExpiredRefund(bytes32 orderId) external nonReentrant {
        Escrow storage item = _requireState(orderId, State.Funded);
        if (msg.sender != item.buyer) revert UnauthorizedParticipant();
        if (block.timestamp <= item.fulfillmentDeadline) revert FulfillmentWindowOpen();
        _refund(orderId, item);
    }

    function resolveDispute(bytes32 orderId, bool releaseToSeller)
        external
        nonReentrant
        onlyRole(ARBITER_ROLE)
    {
        Escrow storage item = _requireState(orderId, State.Disputed);
        if (releaseToSeller) _release(orderId, item);
        else _refund(orderId, item);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Recovers only tokens that are not backing open escrows.
    function recoverExcessToken(IERC20 token, address recipient, uint256 amount)
        external
        nonReentrant
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (recipient == address(0)) revert ZeroAddress();
        if (address(token) == address(paymentToken)) {
            uint256 balance = token.balanceOf(address(this));
            if (balance < totalLiability || amount > balance - totalLiability) revert InsufficientExcessBalance();
        }
        token.safeTransfer(recipient, amount);
        emit ExcessTokenRecovered(address(token), recipient, amount);
    }

    function _requireState(bytes32 orderId, State expected) private view returns (Escrow storage item) {
        item = _escrows[orderId];
        if (item.state != expected) revert InvalidState(expected, item.state);
    }

    function _release(bytes32 orderId, Escrow storage item) private {
        uint256 amount = item.amount;
        address seller = item.seller;
        item.state = State.Released;
        totalLiability -= amount;
        paymentToken.safeTransfer(seller, amount);
        emit EscrowReleased(orderId, seller, amount);
    }

    function _refund(bytes32 orderId, Escrow storage item) private {
        uint256 amount = item.amount;
        address buyer = item.buyer;
        item.state = State.Refunded;
        totalLiability -= amount;
        paymentToken.safeTransfer(buyer, amount);
        emit EscrowRefunded(orderId, buyer, amount);
    }
}
