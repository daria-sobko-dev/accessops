from datetime import timedelta
from pathlib import Path

import pytest

from accessops.catalog import load_catalog
from accessops.errors import InvalidInputError, PolicyDeniedError
from accessops.policy import check_grant_policy, check_ttl_policy, validate_username

CATALOG = load_catalog(Path(__file__).resolve().parent.parent / "roles.yaml")
ADMIN = CATALOG.role("devops_admin")
DEV = CATALOG.role("developer")


# ---- privileged policy ----------------------------------------------------


def test_regular_role_needs_no_approval():
    check_grant_policy(role_name="developer", role=DEV, actor="ivan", approved_by=None)


def test_privileged_without_approver_is_denied():
    with pytest.raises(PolicyDeniedError, match="requires --approved-by"):
        check_grant_policy(role_name="devops_admin", role=ADMIN, actor="ivan", approved_by=None)


@pytest.mark.parametrize("approver", ["ai", "AI", " Ai "])
def test_ai_cannot_approve(approver):
    with pytest.raises(PolicyDeniedError, match="AI cannot approve"):
        check_grant_policy(role_name="devops_admin", role=ADMIN, actor="ivan", approved_by=approver)


@pytest.mark.parametrize("approver", ["ivan", "Ivan"])
def test_self_approval_is_denied(approver):
    with pytest.raises(PolicyDeniedError, match="no self-approval"):
        check_grant_policy(role_name="devops_admin", role=ADMIN, actor="ivan", approved_by=approver)


def test_human_approver_is_allowed():
    check_grant_policy(role_name="devops_admin", role=ADMIN, actor="ivan", approved_by="olga")


# ---- user names -----------------------------------------------------------


@pytest.mark.parametrize("name", ["anna", "anna_k", "dev2", "a1"])
def test_valid_usernames(name):
    assert validate_username(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "a",
        "Anna",
        "anna-k",
        "anna k",
        "2anna",
        "_anna",
        "anna;drop role postgres",
        'anna"',
        "anna\n",
        "анна",
        "a" * 64,
    ],
)
def test_invalid_usernames(name):
    with pytest.raises(InvalidInputError, match="Invalid user name"):
        validate_username(name)


@pytest.mark.parametrize("name", ["postgres", "ai", "pg_monitor", "ao_developer"])
def test_reserved_usernames(name):
    with pytest.raises(InvalidInputError, match="reserved"):
        validate_username(name)


def test_extra_reserved_usernames():
    with pytest.raises(InvalidInputError, match="reserved"):
        validate_username("accessops", extra_reserved={"accessops"})


# ---- ttl policy -------------------------------------------------------------

QA = CATALOG.role("qa")


def test_privileged_requires_ttl():
    with pytest.raises(PolicyDeniedError, match="must be temporary"):
        check_ttl_policy(role_name="devops_admin", role=ADMIN, ttl=None)


@pytest.mark.parametrize("hours", [25, 48])
def test_privileged_ttl_over_24h_is_denied(hours):
    with pytest.raises(PolicyDeniedError, match="longer than the 24h limit"):
        check_ttl_policy(role_name="devops_admin", role=ADMIN, ttl=timedelta(hours=hours))


def test_privileged_ttl_over_role_max_is_denied():
    # devops_admin has max_ttl 12h in roles.yaml, stricter than the 24h limit.
    with pytest.raises(PolicyDeniedError, match="max_ttl 12h"):
        check_ttl_policy(role_name="devops_admin", role=ADMIN, ttl=timedelta(hours=13))


@pytest.mark.parametrize("ttl", [timedelta(minutes=30), timedelta(hours=4), timedelta(hours=12)])
def test_privileged_short_ttl_is_allowed(ttl):
    check_ttl_policy(role_name="devops_admin", role=ADMIN, ttl=ttl)


def test_regular_role_may_be_permanent():
    check_ttl_policy(role_name="developer", role=DEV, ttl=None)


def test_role_max_ttl():
    with pytest.raises(PolicyDeniedError, match="max_ttl 7d: use --ttl"):
        check_ttl_policy(role_name="qa", role=QA, ttl=None)
    with pytest.raises(PolicyDeniedError, match="longer than its max_ttl 7d"):
        check_ttl_policy(role_name="qa", role=QA, ttl=timedelta(days=8))
    check_ttl_policy(role_name="qa", role=QA, ttl=timedelta(days=7))
