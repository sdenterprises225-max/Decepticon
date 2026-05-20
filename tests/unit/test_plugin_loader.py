"""Plugin loader contract tests.

The plugin loader is the OSS↔SaaS extension surface. These tests pin its
behavior so future refactors don't silently break the contract external
plugin packages depend on.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from decepticon import plugin_loader


class _FakeEntryPoint:
    """Stand-in for ``importlib.metadata.EntryPoint`` used in tests."""

    def __init__(self, name: str, value: str, loaded):
        self.name = name
        self.value = value
        self._loaded = loaded

    def load(self):
        return self._loaded


def test_empty_discovery_returns_empty():
    """No entry-points → empty list/dict, no exception."""
    with patch.object(plugin_loader, "entry_points", return_value=[]):
        assert plugin_loader.load_plugin_tools() == []
        assert plugin_loader.load_plugin_middleware() == []
        assert plugin_loader.load_plugin_callbacks() == []
        assert plugin_loader.load_plugin_agents() == {}


def test_list_export_passes_through():
    """A plugin exporting a list is returned as-is (list is not callable)."""
    tool_a = MagicMock(invoke=MagicMock())
    tool_b = MagicMock(invoke=MagicMock())
    ep = _FakeEntryPoint("my-tools", "my_pkg:TOOLS", [tool_a, tool_b])
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_plugin_tools(role="recon")
    assert result == [tool_a, tool_b]


def test_factory_export_is_called_with_role_and_deps():
    """A non-runtime callable export is invoked with role + dep kwargs."""
    captured: dict = {}

    def factory(*, role=None, backend=None):
        captured["role"] = role
        captured["backend"] = backend
        return [MagicMock(invoke=MagicMock())]

    ep = _FakeEntryPoint("my-factory", "my_pkg:factory", factory)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_plugin_tools(role="exploit", backend="sentinel")

    assert captured == {"role": "exploit", "backend": "sentinel"}
    assert len(result) == 1


def test_single_runtime_object_is_wrapped_in_list():
    """A single tool instance (callable but has runtime attrs) is wrapped."""
    tool = MagicMock(invoke=MagicMock())  # passes the runtime-object heuristic
    ep = _FakeEntryPoint("single", "my_pkg:tool", tool)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        assert plugin_loader.load_plugin_tools() == [tool]


def test_broken_load_is_logged_and_skipped(caplog):
    """A plugin that raises in ``.load()`` is skipped; siblings still load."""

    class BrokenEP:
        name = "broken"
        value = "broken_pkg:thing"

        def load(self):
            raise RuntimeError("boom")

    good = MagicMock(invoke=MagicMock())
    eps = [BrokenEP(), _FakeEntryPoint("good", "good:thing", good)]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        with caplog.at_level("ERROR", logger="decepticon.plugin_loader"):
            result = plugin_loader.load_plugin_tools()

    assert result == [good]
    assert any("broken" in record.getMessage() for record in caplog.records)


def test_broken_factory_call_is_logged_and_skipped(caplog):
    """A factory that raises at invocation time is skipped; siblings load."""

    def broken_factory(**kwargs):
        raise RuntimeError("nope")

    good_obj = MagicMock(invoke=MagicMock())
    eps = [
        _FakeEntryPoint("broken-factory", "pkg:f", broken_factory),
        _FakeEntryPoint("good", "pkg:t", good_obj),
    ]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        with caplog.at_level("ERROR", logger="decepticon.plugin_loader"):
            result = plugin_loader.load_plugin_tools()

    assert result == [good_obj]
    assert any("broken-factory" in record.getMessage() for record in caplog.records)


def test_load_plugin_agents_normalizes_to_module_graph():
    """Plugin agent entry-points are normalized to ``module:graph`` paths."""

    class EP:
        def __init__(self, name, value):
            self.name = name
            self.value = value

    eps = [
        EP("compliance", "my_pkg.agents.compliance:create_agent"),
        EP("audit", "my_pkg.agents.audit"),  # module-only form
    ]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        result = plugin_loader.load_plugin_agents()

    assert result == {
        "compliance": "my_pkg.agents.compliance:graph",
        "audit": "my_pkg.agents.audit:graph",
    }


def test_none_result_from_factory_is_dropped():
    """A factory returning None doesn't pollute the output list."""

    def factory(**kwargs):
        return None

    ep = _FakeEntryPoint("noop", "pkg:f", factory)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        assert plugin_loader.load_plugin_tools() == []


# ---------------------------------------------------------------------------
# Subagent discovery — load_subagents_for_parent
# ---------------------------------------------------------------------------


def _spec(name: str, parents=("decepticon",), priority: int = 100, bundle: str | None = None):
    """Construct a SubAgentSpec for tests with a stub factory."""
    return plugin_loader.SubAgentSpec(
        name=name,
        description=f"{name} description",
        factory=lambda: f"{name}-agent",
        parent_agents=tuple(parents),
        bundle=bundle,
        priority=priority,
    )


def test_load_subagents_filters_by_parent():
    """Only specs whose parent_agents includes the requested parent are returned."""
    specs = [
        _spec("recon", parents=("decepticon",)),
        _spec("scanner", parents=("vulnresearch",)),
        _spec("shared-tool", parents=("decepticon", "vulnresearch")),
    ]
    eps = [_FakeEntryPoint(s.name, f"pkg.{s.name}:SUBAGENT_SPEC", s) for s in specs]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        decepticon_specs = plugin_loader.load_subagents_for_parent("decepticon")
        vulnresearch_specs = plugin_loader.load_subagents_for_parent("vulnresearch")

    assert {s.name for s in decepticon_specs} == {"recon", "shared-tool"}
    assert {s.name for s in vulnresearch_specs} == {"scanner", "shared-tool"}


def test_load_subagents_sorted_by_priority_then_name():
    """Returned specs follow (priority asc, name asc) order."""
    specs = [
        _spec("b-late", priority=50),
        _spec("a-early", priority=10),
        _spec("c-also-early", priority=10),
    ]
    eps = [_FakeEntryPoint(s.name, f"pkg.{s.name}:SUBAGENT_SPEC", s) for s in specs]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        result = plugin_loader.load_subagents_for_parent("decepticon")

    assert [s.name for s in result] == ["a-early", "c-also-early", "b-late"]


def test_load_subagents_supports_list_export():
    """Entry-points exporting a list of specs are flattened."""
    bundle = [
        _spec("alpha", priority=10),
        _spec("beta", priority=20),
    ]
    ep = _FakeEntryPoint("bundle", "pkg:BUNDLE", bundle)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_subagents_for_parent("decepticon")

    assert [s.name for s in result] == ["alpha", "beta"]


def test_load_subagents_supports_factory_callable():
    """A callable that returns a SubAgentSpec is invoked."""

    def make_spec():
        return _spec("dynamic", priority=5)

    ep = _FakeEntryPoint("dyn", "pkg:make_spec", make_spec)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_subagents_for_parent("decepticon")

    assert [s.name for s in result] == ["dynamic"]


def test_load_subagents_broken_plugin_is_logged_and_skipped(caplog):
    """A broken subagent plugin is skipped; siblings still load."""

    class BrokenEP:
        name = "broken"
        value = "broken:thing"

        def load(self):
            raise RuntimeError("boom")

    good = _spec("good")
    eps = [BrokenEP(), _FakeEntryPoint("good", "pkg.good:SUBAGENT_SPEC", good)]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        with caplog.at_level("ERROR", logger="decepticon.plugin_loader"):
            result = plugin_loader.load_subagents_for_parent("decepticon")

    assert [s.name for s in result] == ["good"]
    assert any("broken" in record.getMessage() for record in caplog.records)


def test_load_subagents_no_match_returns_empty():
    """Requesting a parent with no matching specs yields an empty list."""
    eps = [_FakeEntryPoint("recon", "pkg.recon:SUBAGENT_SPEC", _spec("recon"))]
    with patch.object(plugin_loader, "entry_points", return_value=eps):
        result = plugin_loader.load_subagents_for_parent("nonexistent")

    assert result == []


def test_load_subagents_factory_is_lazy():
    """SubAgentSpec.factory is NOT invoked during discovery — caller decides."""
    invocations = {"count": 0}

    def factory():
        invocations["count"] += 1
        return "agent-instance"

    spec = plugin_loader.SubAgentSpec(
        name="lazy",
        description="...",
        factory=factory,
        parent_agents=("decepticon",),
    )
    ep = _FakeEntryPoint("lazy", "pkg:SUBAGENT_SPEC", spec)
    with patch.object(plugin_loader, "entry_points", return_value=[ep]):
        result = plugin_loader.load_subagents_for_parent("decepticon")

    assert invocations["count"] == 0  # factory not yet called
    # caller invokes when ready
    assert result[0].factory() == "agent-instance"
    assert invocations["count"] == 1
