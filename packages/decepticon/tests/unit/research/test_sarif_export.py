"""Tests for decepticon.tools.research.sarif_export."""

from __future__ import annotations

import json
from pathlib import Path

from decepticon.tools.research.sarif_export import (
    export_findings_to_sarif,
    severity_threshold_breach,
    write_sarif,
)
from decepticon_core.types.kg import KnowledgeGraph, Node, NodeKind


class _FakeNode:
    def __init__(self, node_id: str, kind: str, label: str, properties: dict):
        self.id = node_id
        self.kind = kind
        self.label = label
        self.properties = properties


class _FakeGraph:
    def __init__(self, nodes: list[_FakeNode]):
        self.nodes = {n.id: n for n in nodes}


def _finding(node_id: str, **props) -> _FakeNode:
    props.setdefault("severity", "high")
    return _FakeNode(node_id, "finding", props.get("title", node_id), props)


def test_export_emits_v2_1_0_envelope():
    graph = _FakeGraph([_finding("f1", title="t", description="d")])
    doc = export_findings_to_sarif(graph)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Decepticon"


def test_export_empty_graph_yields_zero_results():
    doc = export_findings_to_sarif(_FakeGraph([]))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["properties"]["decepticon-finding-count"] == 0


def test_export_groups_results_by_rule_id():
    graph = _FakeGraph(
        [
            _finding("f1", vuln_class="sqli", severity="high"),
            _finding("f2", vuln_class="sqli", severity="high"),
            _finding("f3", vuln_class="xss", severity="medium"),
        ]
    )
    doc = export_findings_to_sarif(graph)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = sorted(r["id"] for r in rules)
    assert rule_ids == ["decepticon/sqli", "decepticon/xss"]
    assert len(doc["runs"][0]["results"]) == 3


def test_export_severity_mapping_to_level():
    graph = _FakeGraph(
        [
            _finding("c", severity="critical"),
            _finding("h", severity="high"),
            _finding("m", severity="medium"),
            _finding("l", severity="low"),
        ]
    )
    doc = export_findings_to_sarif(graph)
    levels = {r["ruleId"][-1]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels == {"c": "error", "h": "error", "m": "warning", "l": "note"}


def test_export_includes_security_severity_property():
    graph = _FakeGraph([_finding("f", severity="critical")])
    doc = export_findings_to_sarif(graph)
    result = doc["runs"][0]["results"][0]
    assert result["properties"]["security-severity"] == "10.0"


def test_export_locations_from_file_and_line():
    graph = _FakeGraph([_finding("f", file="src/auth.py", start_line=42, end_line=44)])
    doc = export_findings_to_sarif(graph)
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/auth.py"
    assert loc["region"]["startLine"] == 42
    assert loc["region"]["endLine"] == 44


def test_export_no_locations_when_file_absent():
    graph = _FakeGraph([_finding("f")])
    doc = export_findings_to_sarif(graph)
    assert "locations" not in doc["runs"][0]["results"][0]


def test_export_rule_id_prefers_cve_over_cwe():
    graph = _FakeGraph([_finding("f", cve="CVE-2024-12345", cwe="89", vuln_class="sqli")])
    doc = export_findings_to_sarif(graph)
    assert doc["runs"][0]["results"][0]["ruleId"] == "decepticon/CVE-2024-12345"


def test_export_rule_id_falls_back_to_technique_then_label():
    graph = _FakeGraph(
        [
            _finding("a", mitre_attack="T1190"),
            _finding("b", title="my-finding-name"),
        ]
    )
    doc = export_findings_to_sarif(graph)
    ids = sorted(r["ruleId"] for r in doc["runs"][0]["results"])
    assert ids == ["decepticon/T1190", "decepticon/my-finding-name"]


def test_severity_threshold_breach_passes_below_threshold():
    graph = _FakeGraph([_finding("low", severity="low"), _finding("med", severity="medium")])
    doc = export_findings_to_sarif(graph)
    assert not severity_threshold_breach(doc, fail_on="high")


def test_severity_threshold_breach_fires_at_or_above():
    graph = _FakeGraph([_finding("h", severity="high")])
    doc = export_findings_to_sarif(graph)
    assert severity_threshold_breach(doc, fail_on="high")


def test_severity_threshold_breach_with_critical_against_high_threshold():
    graph = _FakeGraph([_finding("c", severity="critical")])
    doc = export_findings_to_sarif(graph)
    assert severity_threshold_breach(doc, fail_on="high")


def test_write_sarif_round_trip(tmp_path: Path):
    graph = _FakeGraph([_finding("f", severity="high", vuln_class="sqli")])
    out_path = tmp_path / "out" / "scan.sarif"
    written = write_sarif(graph, out_path, engagement_name="testing")
    assert written.exists()
    doc = json.loads(written.read_text(encoding="utf-8"))
    assert doc["runs"][0]["properties"]["decepticon-engagement"] == "testing"
    assert len(doc["runs"][0]["results"]) == 1


def test_export_default_severity_is_medium_when_missing():
    node = _FakeNode("f", "finding", "f", {})
    doc = export_findings_to_sarif(_FakeGraph([node]))
    assert doc["runs"][0]["results"][0]["level"] == "warning"


def _real_finding_graph(**props) -> KnowledgeGraph:
    g = KnowledgeGraph()
    g.upsert_node(Node.make(NodeKind.FINDING, props.pop("label", "SQLi in /search"), **props))
    return g


def test_export_reads_real_node_props_for_severity():
    graph = _real_finding_graph(severity="high")
    result = export_findings_to_sarif(graph)["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["security-severity"] == "7.0"


def test_export_real_node_critical_security_severity():
    graph = _real_finding_graph(severity="critical")
    result = export_findings_to_sarif(graph)["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["security-severity"] == "10.0"


def test_export_real_node_cwe_list_yields_well_formed_rule_id():
    graph = _real_finding_graph(severity="high", cwe=["CWE-89"])
    rule_id = export_findings_to_sarif(graph)["runs"][0]["results"][0]["ruleId"]
    assert rule_id == "decepticon/CWE-89"
    assert "[" not in rule_id and "'" not in rule_id


def test_export_real_node_first_cwe_wins_when_list():
    graph = _real_finding_graph(severity="high", cwe=["CWE-78", "CWE-77"])
    rule_id = export_findings_to_sarif(graph)["runs"][0]["results"][0]["ruleId"]
    assert rule_id == "decepticon/CWE-78"


def test_export_real_node_emits_file_and_line_locations():
    graph = _real_finding_graph(severity="high", file="src/auth.py", line=42)
    loc = export_findings_to_sarif(graph)["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"
    ]
    assert loc["artifactLocation"]["uri"] == "src/auth.py"
    assert loc["region"]["startLine"] == 42


def test_severity_threshold_breach_fires_on_real_high_finding():
    graph = _real_finding_graph(severity="high", cwe=["CWE-89"], file="src/auth.py", line=42)
    doc = export_findings_to_sarif(graph)
    assert severity_threshold_breach(doc, fail_on="high")


def test_severity_threshold_breach_fires_on_real_critical_finding():
    graph = _real_finding_graph(severity="critical", cwe=["CWE-918"])
    doc = export_findings_to_sarif(graph)
    assert severity_threshold_breach(doc, fail_on="high")
