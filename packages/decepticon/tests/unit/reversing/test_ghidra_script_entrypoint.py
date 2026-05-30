from __future__ import annotations

from decepticon.tools.reversing.scripts import ghidra_recon_script


class TestGhidraReconScriptEntrypoint:
    def test_no_iterable_getentrypoint(self) -> None:
        src = ghidra_recon_script("/workspace/target")
        assert "for a in f.getEntryPoint()" not in src

    def test_addrs_variable_absent(self) -> None:
        src = ghidra_recon_script("/workspace/target")
        assert "addrs" not in src

    def test_entrypoint_printed_once(self) -> None:
        src = ghidra_recon_script("/workspace/target")
        assert src.count("getEntryPoint()") == 1

    def test_binary_path_substituted(self) -> None:
        src = ghidra_recon_script("/tmp/malware.exe")
        assert "/tmp/malware.exe" in src
