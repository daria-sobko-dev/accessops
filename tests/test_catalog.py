import copy
from pathlib import Path

import pytest
import yaml

from accessops.catalog import load_catalog, parse_catalog
from accessops.errors import CatalogError, InvalidInputError

ROLES_FILE = Path(__file__).resolve().parent.parent / "roles.yaml"


@pytest.fixture
def raw() -> dict:
    return yaml.safe_load(ROLES_FILE.read_text())


def test_real_catalog_loads():
    catalog = load_catalog(ROLES_FILE)
    assert set(catalog.roles) == {"developer", "analyst", "qa", "devops_admin"}
    assert catalog.targets.postgres.database == "appdb"
    assert catalog.targets.postgres.schema_name == "app"
    assert catalog.targets.rabbitmq.vhost == "app"


def test_only_devops_admin_is_privileged():
    catalog = load_catalog(ROLES_FILE)
    privileged = {name for name, role in catalog.roles.items() if role.privileged}
    assert privileged == {"devops_admin"}


def test_analyst_is_read_only():
    role = load_catalog(ROLES_FILE).role("analyst")
    assert role.postgres.table_privileges == ["SELECT"]
    assert role.rabbitmq.write == "" and role.rabbitmq.configure == ""


def test_unknown_field_is_rejected(raw):
    raw["roles"]["developer"]["postgress"] = {}
    with pytest.raises(CatalogError, match=r"roles\.developer\.postgress: Extra inputs"):
        parse_catalog(raw)


def test_unknown_privilege_is_rejected(raw):
    raw["roles"]["analyst"]["postgres"]["table_privileges"] = ["SELECT", "DROP"]
    with pytest.raises(CatalogError, match=r"roles\.analyst\.postgres\.table_privileges\.1"):
        parse_catalog(raw)


def test_privileged_flag_is_required(raw):
    del raw["roles"]["qa"]["privileged"]
    with pytest.raises(CatalogError, match=r"roles\.qa\.privileged: Field required"):
        parse_catalog(raw)


def test_admin_rights_without_privileged_flag_are_rejected(raw):
    bad = copy.deepcopy(raw)
    bad["roles"]["devops_admin"]["privileged"] = False
    with pytest.raises(CatalogError, match="not marked privileged"):
        parse_catalog(bad)


def test_invalid_rabbit_regex_is_rejected(raw):
    raw["roles"]["qa"]["rabbitmq"]["read"] = "(["
    with pytest.raises(CatalogError, match="not a valid regular expression"):
        parse_catalog(raw)


def test_invalid_role_name_is_rejected(raw):
    raw["roles"]["Bad-Name"] = raw["roles"]["qa"]
    with pytest.raises(CatalogError, match="Bad-Name"):
        parse_catalog(raw)


def test_unknown_role_lookup():
    with pytest.raises(InvalidInputError, match="Unknown role 'superuser'"):
        load_catalog(ROLES_FILE).role("superuser")


def test_broken_yaml(tmp_path):
    path = tmp_path / "roles.yaml"
    path.write_text("roles: [unclosed")
    with pytest.raises(CatalogError, match="not valid YAML"):
        load_catalog(path)


def test_missing_file(tmp_path):
    with pytest.raises(CatalogError, match="not found"):
        load_catalog(tmp_path / "nope.yaml")


# ---- linux section --------------------------------------------------------


def test_linux_groups_from_catalog():
    catalog = load_catalog(ROLES_FILE)
    assert catalog.role("developer").linux.groups == ["developers"]
    assert catalog.role("devops_admin").linux.sudo is True
    assert all(not role.linux.sudo for role in catalog.roles.values() if not role.privileged)


def test_sudo_in_non_privileged_role_is_rejected(raw):
    raw["roles"]["developer"]["linux"]["sudo"] = True
    with pytest.raises(CatalogError, match=r"roles\.developer.*linux\.sudo.*not marked privileged"):
        parse_catalog(raw)


@pytest.mark.parametrize("group", ["sudo", "docker", "wheel", "root"])
def test_admin_linux_group_in_non_privileged_role_is_rejected(raw, group):
    raw["roles"]["qa"]["linux"]["groups"] = ["qa", group]
    with pytest.raises(CatalogError, match=f"linux groups {group}.*not marked privileged"):
        parse_catalog(raw)


def test_linux_section_is_required(raw):
    del raw["roles"]["analyst"]["linux"]
    with pytest.raises(CatalogError, match=r"roles\.analyst\.linux: Field required"):
        parse_catalog(raw)


@pytest.mark.parametrize("groups", [[], ["Bad Group"], ["dev;rm"], ["qa", "qa"]])
def test_invalid_linux_groups_are_rejected(raw, groups):
    raw["roles"]["qa"]["linux"]["groups"] = groups
    with pytest.raises(CatalogError, match=r"roles\.qa\.linux\.groups"):
        parse_catalog(raw)


def test_unknown_linux_field_is_rejected(raw):
    raw["roles"]["qa"]["linux"]["shell"] = "/bin/zsh"
    with pytest.raises(CatalogError, match=r"roles\.qa\.linux\.shell: Extra inputs"):
        parse_catalog(raw)


# ---- max_ttl ----------------------------------------------------------------


def test_max_ttl_is_parsed():
    from datetime import timedelta

    catalog = load_catalog(ROLES_FILE)
    assert catalog.role("qa").max_ttl == timedelta(days=7)
    assert catalog.role("devops_admin").max_ttl == timedelta(hours=12)
    assert catalog.role("developer").max_ttl is None


@pytest.mark.parametrize("value", ["7 days", "1w", "0h", "", "12", "1.5d"])
def test_invalid_max_ttl_format_is_rejected(raw, value):
    raw["roles"]["qa"]["max_ttl"] = value
    with pytest.raises(CatalogError, match=r"roles\.qa\.max_ttl.*invalid duration"):
        parse_catalog(raw)


def test_privileged_max_ttl_over_24h_is_rejected(raw):
    raw["roles"]["devops_admin"]["max_ttl"] = "2d"
    with pytest.raises(CatalogError, match="longer than the 24h limit for privileged roles"):
        parse_catalog(raw)
