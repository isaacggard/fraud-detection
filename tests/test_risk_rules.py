import pytest
from risk_rules import label_risk, score_transaction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def base_tx(**overrides):
    """Neutral transaction that scores 0: all signals at their lowest tier."""
    tx = {
        "device_risk_score": 10,   # < 40, no points
        "is_international": 0,
        "amount_usd": 100,         # < 500, no points
        "velocity_24h": 1,         # < 3, no points
        "failed_logins_24h": 0,    # < 2, no points
        "prior_chargebacks": 0,
    }
    tx.update(overrides)
    return tx


# ---------------------------------------------------------------------------
# Existing tests (kept for regression)
# ---------------------------------------------------------------------------

def test_label_risk_thresholds():
    assert label_risk(10) == "low"
    assert label_risk(35) == "medium"
    assert label_risk(75) == "high"


def test_large_amount_adds_risk():
    tx = base_tx(amount_usd=1200)
    assert score_transaction(tx) >= 25


# ---------------------------------------------------------------------------
# Flaw 1 — device_risk_score >= 70 must INCREASE the score
# ---------------------------------------------------------------------------

def test_high_device_risk_scores_higher_than_no_device_risk():
    # A device score of 80 is a strong fraud signal and must add points.
    low_device = score_transaction(base_tx(device_risk_score=10))
    high_device = score_transaction(base_tx(device_risk_score=80))
    assert high_device > low_device, (
        f"device_risk_score=80 should score higher than 10, got {high_device} vs {low_device}"
    )


def test_highest_device_risk_scores_higher_than_mid_device_risk():
    # The >= 70 tier must be MORE penalizing than the 40–69 tier, not less.
    mid_device = score_transaction(base_tx(device_risk_score=50))   # 40–69 band
    high_device = score_transaction(base_tx(device_risk_score=80))  # >= 70 band
    assert high_device > mid_device, (
        f"device_risk_score=80 should score higher than 50, got {high_device} vs {mid_device}"
    )


def test_device_risk_boundary_at_70():
    # Score must not drop when crossing the >= 70 threshold.
    below = score_transaction(base_tx(device_risk_score=69))
    at = score_transaction(base_tx(device_risk_score=70))
    assert at > below, (
        f"device_risk_score=70 should score higher than 69, got {at} vs {below}"
    )


# ---------------------------------------------------------------------------
# Flaw 2 — is_international == 1 must INCREASE the score
# ---------------------------------------------------------------------------

def test_international_transaction_scores_higher_than_domestic():
    domestic = score_transaction(base_tx(is_international=0))
    international = score_transaction(base_tx(is_international=1))
    assert international > domestic, (
        f"international transaction should score higher than domestic, got {international} vs {domestic}"
    )


def test_international_flag_adds_positive_points():
    # The delta itself must be positive, not just comparatively higher.
    domestic = score_transaction(base_tx(is_international=0))
    international = score_transaction(base_tx(is_international=1))
    assert international - domestic > 0


# ---------------------------------------------------------------------------
# Flaw 3 — velocity_24h >= 6 must INCREASE the score
# ---------------------------------------------------------------------------

def test_high_velocity_scores_higher_than_low_velocity():
    low_vel = score_transaction(base_tx(velocity_24h=1))
    high_vel = score_transaction(base_tx(velocity_24h=8))
    assert high_vel > low_vel, (
        f"velocity=8 should score higher than velocity=1, got {high_vel} vs {low_vel}"
    )


def test_highest_velocity_scores_higher_than_mid_velocity():
    # The >= 6 tier must be MORE penalizing than the 3–5 tier, not less.
    mid_vel = score_transaction(base_tx(velocity_24h=4))   # 3–5 band
    high_vel = score_transaction(base_tx(velocity_24h=8))  # >= 6 band
    assert high_vel > mid_vel, (
        f"velocity=8 should score higher than velocity=4, got {high_vel} vs {mid_vel}"
    )


def test_velocity_boundary_at_6():
    below = score_transaction(base_tx(velocity_24h=5))
    at = score_transaction(base_tx(velocity_24h=6))
    assert at > below, (
        f"velocity=6 should score higher than velocity=5, got {at} vs {below}"
    )


# ---------------------------------------------------------------------------
# Flaw 4 — prior_chargebacks must INCREASE the score
# ---------------------------------------------------------------------------

def test_one_prior_chargeback_scores_higher_than_none():
    no_cb = score_transaction(base_tx(prior_chargebacks=0))
    one_cb = score_transaction(base_tx(prior_chargebacks=1))
    assert one_cb > no_cb, (
        f"prior_chargebacks=1 should score higher than 0, got {one_cb} vs {no_cb}"
    )


def test_two_prior_chargebacks_scores_higher_than_one():
    one_cb = score_transaction(base_tx(prior_chargebacks=1))
    two_cb = score_transaction(base_tx(prior_chargebacks=2))
    assert two_cb > one_cb, (
        f"prior_chargebacks=2 should score higher than 1, got {two_cb} vs {one_cb}"
    )


def test_repeat_chargeback_account_scores_highest():
    no_cb = score_transaction(base_tx(prior_chargebacks=0))
    many_cb = score_transaction(base_tx(prior_chargebacks=3))
    assert many_cb > no_cb


# ---------------------------------------------------------------------------
# Integration — confirmed chargeback transactions must reach "high" risk
# ---------------------------------------------------------------------------
# Profiles taken directly from transactions.csv + accounts.csv.
# Each of these resulted in a real chargeback loss.

@pytest.mark.parametrize("tx,expected_label,description", [
    (
        # tx 50003: $1,250 loss — gift cards, PH, device=81, vel=6, 5 failed logins
        {
            "device_risk_score": 81, "is_international": 1, "amount_usd": 1250,
            "velocity_24h": 6, "failed_logins_24h": 5, "prior_chargebacks": 0,
        },
        "high",
        "tx50003 gift_cards PH $1250",
    ),
    (
        # tx 50011: $1,400 loss — crypto, RU, device=85, vel=8, 7 failed logins
        {
            "device_risk_score": 85, "is_international": 1, "amount_usd": 1400,
            "velocity_24h": 8, "failed_logins_24h": 7, "prior_chargebacks": 1,
        },
        "high",
        "tx50011 crypto RU $1400",
    ),
    (
        # tx 50006: $400 loss — electronics, NG, device=77, vel=7, 6 failed logins, 3 prior cb
        {
            "device_risk_score": 77, "is_international": 1, "amount_usd": 399,
            "velocity_24h": 7, "failed_logins_24h": 6, "prior_chargebacks": 3,
        },
        "high",
        "tx50006 electronics NG $400",
    ),
    (
        # tx 50014: $50 loss — gaming, NG, device=72, vel=9, 7 failed logins, 3 prior cb
        {
            "device_risk_score": 72, "is_international": 1, "amount_usd": 49,
            "velocity_24h": 9, "failed_logins_24h": 7, "prior_chargebacks": 3,
        },
        "high",
        "tx50014 gaming NG $50",
    ),
    (
        # tx 50019: $75 loss — gaming, RU, device=83, vel=10, 8 failed logins
        {
            "device_risk_score": 83, "is_international": 1, "amount_usd": 75,
            "velocity_24h": 10, "failed_logins_24h": 8, "prior_chargebacks": 1,
        },
        "high",
        "tx50019 gaming RU $75",
    ),
    (
        # tx 50013: $150 loss — gift cards, PH, device=79, vel=7, 5 failed logins
        {
            "device_risk_score": 79, "is_international": 1, "amount_usd": 150,
            "velocity_24h": 7, "failed_logins_24h": 5, "prior_chargebacks": 0,
        },
        "high",
        "tx50013 gift_cards PH $150",
    ),
    (
        # tx 50015: $910 loss — electronics, IN, device=71, vel=6, 4 failed logins
        {
            "device_risk_score": 71, "is_international": 1, "amount_usd": 910,
            "velocity_24h": 6, "failed_logins_24h": 4, "prior_chargebacks": 0,
        },
        "high",
        "tx50015 electronics IN $910",
    ),
])
def test_confirmed_chargeback_is_high_risk(tx, expected_label, description):
    score = score_transaction(tx)
    label = label_risk(score)
    assert label == expected_label, (
        f"{description}: expected '{expected_label}' but got '{label}' (score={score})"
    )


# ---------------------------------------------------------------------------
# Sanity — clean domestic transactions must not be over-penalized
# ---------------------------------------------------------------------------

def test_clean_low_value_domestic_transaction_is_low_risk():
    # A routine small domestic purchase with no risk signals should stay low.
    tx = base_tx(amount_usd=45, device_risk_score=8)
    assert label_risk(score_transaction(tx)) == "low"


def test_large_vip_domestic_transaction_does_not_reach_high():
    # High-value but otherwise clean domestic transaction should not be flagged high.
    tx = base_tx(amount_usd=2400, device_risk_score=55, velocity_24h=1)
    label = label_risk(score_transaction(tx))
    assert label in ("low", "medium"), f"Clean large domestic tx should not be high, got {label}"
