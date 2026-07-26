// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

interface IAggregatorV3Like {
    function decimals() external view returns (uint8);

    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// @title SAFER multi-source price oracle guard
/// @notice Optional adapter for future currency conversion. The fixed-price
///         escrow does not depend on this contract.
/// @dev Aggregates independent feeds, normalizes decimals, rejects stale and
///      incomplete rounds, rejects outliers, and fails closed without quorum.
contract SaferOracleGuard {
    uint256 public constant BPS = 10_000;
    uint256 public constant NORMALIZED_DECIMALS = 18;
    uint256 public constant MAX_FEEDS = 7;

    error InvalidConfiguration();
    error DuplicateFeed();
    error InsufficientQuorum(uint256 valid, uint256 required);
    error PriceOutOfBounds(uint256 price);
    error ExcessiveDeviation(uint256 inliers, uint256 required);
    error UpdateTooSoon(uint256 nextUpdateAt);
    error PriceChangeTooLarge(uint256 previousPrice, uint256 candidatePrice);
    error SafePriceUnavailable();

    event SafePriceUpdated(uint256 indexed price, uint256 observationTime, uint256 sourceCount);

    address[] public feeds;
    uint256 public immutable maxAge;
    uint256 public immutable minPrice;
    uint256 public immutable maxPrice;
    uint256 public immutable maxDeviationBps;
    uint256 public immutable minQuorum;
    uint256 public immutable minUpdateInterval;
    uint256 public immutable maxUpdateChangeBps;
    uint256 public lastGoodPrice;
    uint256 public lastUpdatedAt;

    constructor(
        address[] memory feedAddresses,
        uint256 maximumAge,
        uint256 minimumPrice,
        uint256 maximumPrice,
        uint256 maximumDeviationBps,
        uint256 minimumQuorum,
        uint256 minimumUpdateInterval,
        uint256 maximumUpdateChangeBps
    ) {
        uint256 count = feedAddresses.length;
        if (
            count < 3 || count > MAX_FEEDS || maximumAge == 0 || minimumPrice == 0 || minimumPrice >= maximumPrice
                || maximumPrice > type(uint256).max / BPS || maximumDeviationBps == 0
                || maximumDeviationBps > BPS || minimumQuorum < 2 || minimumQuorum > count
                || minimumQuorum <= count / 2 || minimumUpdateInterval == 0 || minimumUpdateInterval > maximumAge
                || maximumUpdateChangeBps == 0 || maximumUpdateChangeBps > BPS
        ) revert InvalidConfiguration();

        for (uint256 i = 0; i < count; ++i) {
            address feed = feedAddresses[i];
            if (feed == address(0) || feed.code.length == 0) revert InvalidConfiguration();
            for (uint256 j = 0; j < i; ++j) if (feedAddresses[j] == feed) revert DuplicateFeed();
            feeds.push(feed);
        }

        maxAge = maximumAge;
        minPrice = minimumPrice;
        maxPrice = maximumPrice;
        maxDeviationBps = maximumDeviationBps;
        minQuorum = minimumQuorum;
        minUpdateInterval = minimumUpdateInterval;
        maxUpdateChangeBps = maximumUpdateChangeBps;
    }

    function feedCount() external view returns (uint256) {
        return feeds.length;
    }

    /// @return price Median normalized to 18 decimals.
    /// @return validSources Number of fresh and complete responses before outlier filtering.
    /// @return oldestObservation Oldest timestamp among responses used to calculate the result.
    function readSafePrice() external view returns (uint256 price, uint256 validSources, uint256 oldestObservation) {
        return _readSafePrice();
    }

    /// @notice Persists a guarded price for consumers that require a rate-limited value.
    /// @dev Anyone may update because all inputs are immutable feeds. The interval and
    ///      maximum-change circuit breaker prevent same-block and abrupt price swings.
    function updateSafePrice() external returns (uint256 price) {
        if (lastUpdatedAt != 0 && block.timestamp < lastUpdatedAt + minUpdateInterval) {
            revert UpdateTooSoon(lastUpdatedAt + minUpdateInterval);
        }
        uint256 validSources;
        uint256 oldestObservation;
        (price, validSources, oldestObservation) = _readSafePrice();
        uint256 previous = lastGoodPrice;
        if (previous != 0) {
            uint256 difference = price > previous ? price - previous : previous - price;
            if ((difference * BPS) / previous > maxUpdateChangeBps) revert PriceChangeTooLarge(previous, price);
        }
        lastGoodPrice = price;
        lastUpdatedAt = block.timestamp;
        emit SafePriceUpdated(price, oldestObservation, validSources);
    }

    function latestSafePrice() external view returns (uint256 price, uint256 updatedAt) {
        price = lastGoodPrice;
        updatedAt = lastUpdatedAt;
        if (price == 0 || updatedAt == 0 || block.timestamp - updatedAt > maxAge) revert SafePriceUnavailable();
    }

    function _readSafePrice() private view returns (uint256 price, uint256 validSources, uint256 oldestObservation) {
        uint256[] memory values = new uint256[](feeds.length);
        oldestObservation = type(uint256).max;

        for (uint256 i = 0; i < feeds.length; ++i) {
            (bool valid, uint256 value, uint256 updatedAt) = _readFeed(feeds[i]);
            if (!valid) continue;
            values[validSources] = value;
            ++validSources;
            if (updatedAt < oldestObservation) oldestObservation = updatedAt;
        }

        if (validSources < minQuorum) revert InsufficientQuorum(validSources, minQuorum);
        _sort(values, validSources);
        price = _median(values, validSources);
        if (price < minPrice || price > maxPrice) revert PriceOutOfBounds(price);

        uint256 inliers;
        for (uint256 i = 0; i < validSources; ++i) {
            uint256 difference = values[i] > price ? values[i] - price : price - values[i];
            if ((difference * BPS) / price <= maxDeviationBps) ++inliers;
        }
        if (inliers < minQuorum) revert ExcessiveDeviation(inliers, minQuorum);
    }

    function _readFeed(address feed) private view returns (bool valid, uint256 value, uint256 updatedAt) {
        try IAggregatorV3Like(feed).latestRoundData() returns (
            uint80 roundId,
            int256 answer,
            uint256,
            uint256 observationTime,
            uint80 answeredInRound
        ) {
            if (
                roundId == 0 || answer <= 0 || observationTime == 0 || observationTime > block.timestamp
                    || block.timestamp - observationTime > maxAge || answeredInRound < roundId
            ) return (false, 0, 0);

            try IAggregatorV3Like(feed).decimals() returns (uint8 sourceDecimals) {
                if (sourceDecimals > NORMALIZED_DECIMALS) return (false, 0, 0);
                uint256 scale = 10 ** (NORMALIZED_DECIMALS - sourceDecimals);
                uint256 unsignedAnswer = uint256(answer);
                if (unsignedAnswer > type(uint256).max / scale) return (false, 0, 0);
                value = unsignedAnswer * scale;
                if (value < minPrice || value > maxPrice) return (false, 0, 0);
                return (true, value, observationTime);
            } catch {
                return (false, 0, 0);
            }
        } catch {
            return (false, 0, 0);
        }
    }

    function _sort(uint256[] memory values, uint256 length) private pure {
        for (uint256 i = 1; i < length; ++i) {
            uint256 current = values[i];
            uint256 j = i;
            while (j > 0 && values[j - 1] > current) {
                values[j] = values[j - 1];
                --j;
            }
            values[j] = current;
        }
    }

    function _median(uint256[] memory values, uint256 length) private pure returns (uint256) {
        uint256 middle = length / 2;
        if (length % 2 == 1) return values[middle];
        uint256 lower = values[middle - 1];
        return lower + ((values[middle] - lower) / 2);
    }
}
