// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {SaferOracleGuard} from "../src/SaferOracleGuard.sol";

interface OracleVm {
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 selector) external;
    function expectPartialRevert(bytes4 selector) external;
}

contract MockAggregator {
    uint8 public immutable decimals;
    uint80 public roundId = 1;
    int256 public answer;
    uint256 public updatedAt;
    uint80 public answeredInRound = 1;
    bool public shouldRevert;

    constructor(uint8 sourceDecimals, int256 initialAnswer) {
        decimals = sourceDecimals;
        answer = initialAnswer;
        updatedAt = block.timestamp;
    }

    function setRound(uint80 newRoundId, int256 newAnswer, uint256 newUpdatedAt, uint80 newAnsweredInRound)
        external
    {
        roundId = newRoundId;
        answer = newAnswer;
        updatedAt = newUpdatedAt;
        answeredInRound = newAnsweredInRound;
    }

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        if (shouldRevert) revert("feed unavailable");
        return (roundId, answer, updatedAt, updatedAt, answeredInRound);
    }
}

contract SaferOracleGuardTest {
    OracleVm private constant vm = OracleVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant ONE = 1e18;

    function testNormalizesDecimalsAndReturnsMedian() public {
        MockAggregator a = new MockAggregator(8, 2_000e8);
        MockAggregator b = new MockAggregator(18, 2_010e18);
        MockAggregator c = new MockAggregator(8, 1_990e8);
        SaferOracleGuard guard = _guard(a, b, c, 2, 500);

        (uint256 price, uint256 valid,) = guard.readSafePrice();
        _assertEq(price, 2_000 * ONE, "median");
        _assertEq(valid, 3, "valid count");
    }

    function testSingleManipulatedSpotPriceIsRejectedAsOutlier() public {
        MockAggregator a = new MockAggregator(8, 2_000e8);
        MockAggregator b = new MockAggregator(8, 2_010e8);
        MockAggregator c = new MockAggregator(8, 4_000e8);
        SaferOracleGuard guard = _guard(a, b, c, 2, 500);

        (uint256 price,,) = guard.readSafePrice();
        _assertEq(price, 2_010 * ONE, "honest median");
    }

    function testStaleOrIncompleteFeedsFailClosedWithoutQuorum() public {
        vm.warp(10 days);
        MockAggregator a = new MockAggregator(8, 2_000e8);
        MockAggregator b = new MockAggregator(8, 2_010e8);
        MockAggregator c = new MockAggregator(8, 1_990e8);
        a.setRound(2, 2_000e8, block.timestamp - 2 hours, 2);
        b.setRound(3, 2_010e8, block.timestamp, 2);
        SaferOracleGuard guard = _guard(a, b, c, 2, 500);

        vm.expectPartialRevert(SaferOracleGuard.InsufficientQuorum.selector);
        guard.readSafePrice();
    }

    function testWideSourceDeviationTripsCircuitBreaker() public {
        MockAggregator a = new MockAggregator(8, 1_000e8);
        MockAggregator b = new MockAggregator(8, 2_000e8);
        MockAggregator c = new MockAggregator(8, 4_000e8);
        SaferOracleGuard guard = _guard(a, b, c, 2, 500);

        vm.expectPartialRevert(SaferOracleGuard.ExcessiveDeviation.selector);
        guard.readSafePrice();
    }

    function testFeedRevertIsContainedAndQuorumStillRequired() public {
        MockAggregator a = new MockAggregator(8, 2_000e8);
        MockAggregator b = new MockAggregator(8, 2_010e8);
        MockAggregator c = new MockAggregator(8, 1_990e8);
        c.setShouldRevert(true);
        SaferOracleGuard guard = _guard(a, b, c, 2, 500);

        (uint256 price, uint256 valid,) = guard.readSafePrice();
        _assertEq(price, 2_005 * ONE, "two-source median");
        _assertEq(valid, 2, "valid count");
    }

    function testPersistedPriceRateLimitAndAbruptChangeCircuitBreaker() public {
        MockAggregator a = new MockAggregator(8, 2_000e8);
        MockAggregator b = new MockAggregator(8, 2_010e8);
        MockAggregator c = new MockAggregator(8, 1_990e8);
        SaferOracleGuard guard = _guard(a, b, c, 2, 500);
        guard.updateSafePrice();

        vm.expectPartialRevert(SaferOracleGuard.UpdateTooSoon.selector);
        guard.updateSafePrice();

        vm.warp(block.timestamp + 5 minutes);
        a.setRound(2, 3_000e8, block.timestamp, 2);
        b.setRound(2, 3_010e8, block.timestamp, 2);
        c.setRound(2, 2_990e8, block.timestamp, 2);
        vm.expectPartialRevert(SaferOracleGuard.PriceChangeTooLarge.selector);
        guard.updateSafePrice();
    }

    function _guard(
        MockAggregator a,
        MockAggregator b,
        MockAggregator c,
        uint256 quorum,
        uint256 maxDeviationBps
    ) private returns (SaferOracleGuard) {
        address[] memory feeds = new address[](3);
        feeds[0] = address(a);
        feeds[1] = address(b);
        feeds[2] = address(c);
        return new SaferOracleGuard(feeds, 1 hours, 500 * ONE, 5_000 * ONE, maxDeviationBps, quorum, 5 minutes, 1_000);
    }

    function _assertEq(uint256 actual, uint256 expected, string memory message) private pure {
        require(actual == expected, message);
    }
}
