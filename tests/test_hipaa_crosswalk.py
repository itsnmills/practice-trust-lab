import re

import hipaa_crosswalk as hc
import pytest
from practice_render.rules import HIPAA_BY_GROUP, RULES, cites_for

CITE_RE = re.compile(r"^164\.\d{3}(\([A-Za-z0-9]+\))+$")


def all_cites():
    return {c for cites in hc.CROSSWALK.values() for c in cites}


@pytest.mark.parametrize("cite", sorted(all_cites()))
def test_citation_is_well_formed(cite):
    assert CITE_RE.match(cite.section), cite
    assert cite.kind in {"standard", "required", "addressable", "privacy"}
    assert cite.title


def test_privacy_rule_cites_live_in_part_502():
    for c in all_cites():
        assert (c.kind == "privacy") == c.section.startswith("164.5"), c


def test_security_rule_cites_live_in_308_310_312():
    for c in all_cites():
        if c.kind != "privacy":
            assert c.section.split("(")[0] in {"164.308", "164.310", "164.312"}, c


def test_unknown_group_has_no_cites_and_formats_in_order():
    assert hc.cites_for("nope") == ()
    assert hc.format_cites(hc.cites_for("scribe")) == "\u00a7164.308(b)(1); \u00a7164.502(e)(1)"


def test_crosswalk_is_the_registry_group_table():
    assert hc.CROSSWALK is HIPAA_BY_GROUP
    assert hc.cites_for is cites_for


def test_every_rule_inherits_its_group_citations():
    for rule in RULES.values():
        assert rule.hipaa == hc.cites_for(rule.group), rule.rule_id


def test_every_mapped_group_has_at_least_one_rule():
    rule_groups = {rule.group for rule in RULES.values()}
    assert set(hc.CROSSWALK) <= rule_groups


def test_registry_has_no_orphan_citation_group():
    rule_groups = {rule.group for rule in RULES.values() if rule.group != "other"}
    assert rule_groups <= set(hc.CROSSWALK)
