"""Tests for cross-platform action executors."""


from sentinelforge.core.executors import (
    QUARANTINE_DIR,
    _validate_ip,
    _validate_not_self,
    block_ip,
    disable_account,
    isolate_host,
    kill_process,
    quarantine_file,
    restore_file,
    unblock_ip,
)


class TestIPValidation:
    def test_valid_ip(self):
        assert _validate_ip("192.168.1.1")
        assert _validate_ip("10.0.0.1")
        assert _validate_ip("255.255.255.255")

    def test_invalid_ip(self):
        assert not _validate_ip("999.999.999.999")
        assert not _validate_ip("abc.def.ghi.jkl")
        assert not _validate_ip("192.168.1")
        assert not _validate_ip("")

    def test_self_address_blocked(self):
        assert not _validate_not_self("127.0.0.1")
        assert not _validate_not_self("0.0.0.0")
        assert _validate_not_self("10.0.0.1")


class TestBlockIP:
    def test_invalid_ip_rejected(self):
        result = block_ip("not-an-ip")
        assert not result.success
        assert "Invalid IP" in result.output

    def test_self_block_rejected(self):
        result = block_ip("127.0.0.1")
        assert not result.success
        assert "self-address" in result.output

    def test_canary_mode(self):
        result = block_ip("10.0.0.99", canary=True)
        assert result.success
        assert result.canary
        assert "CANARY" in result.output
        assert "10.0.0.99" in result.command_preview

    def test_unblock_invalid_ip(self):
        result = unblock_ip("not-an-ip")
        assert not result.success


class TestKillProcess:
    def test_low_pid_rejected(self):
        result = kill_process("0")
        assert not result.success
        assert "system process" in result.output

    def test_protected_process_rejected(self):
        result = kill_process("svchost.exe")
        assert not result.success
        assert "protected" in result.output

    def test_invalid_name_rejected(self):
        result = kill_process("rm -rf /;bad")
        assert not result.success
        assert "Invalid" in result.output

    def test_canary_mode_pid(self):
        result = kill_process("12345", canary=True)
        assert result.success
        assert result.canary
        assert "CANARY" in result.output

    def test_canary_mode_name(self):
        result = kill_process("malware.exe", canary=True)
        assert result.success
        assert result.canary

    def test_own_pid_rejected(self):
        import os
        result = kill_process(str(os.getpid()))
        assert not result.success
        assert "own process" in result.output


class TestDisableAccount:
    def test_invalid_username_rejected(self):
        result = disable_account("user;rm -rf /")
        assert not result.success

    def test_protected_account_rejected(self):
        result = disable_account("administrator")
        assert not result.success
        assert "protected" in result.output

    def test_root_rejected(self):
        result = disable_account("root")
        assert not result.success

    def test_canary_mode(self):
        result = disable_account("suspicious_user", canary=True)
        assert result.success
        assert result.canary
        assert "suspicious_user" in result.command_preview


class TestQuarantineFile:
    def test_forbidden_chars_rejected(self):
        result = quarantine_file("/tmp/file;rm -rf /")
        assert not result.success
        assert "Forbidden" in result.output

    def test_nonexistent_file(self):
        result = quarantine_file("/tmp/nonexistent_file_xyz_12345")
        assert not result.success
        assert "not found" in result.output

    def test_canary_mode(self, tmp_path):
        test_file = tmp_path / "suspicious.exe"
        test_file.write_text("malware content")
        result = quarantine_file(str(test_file), canary=True)
        assert result.success
        assert result.canary
        assert test_file.exists()  # file should NOT be moved in canary

    def test_real_quarantine(self, tmp_path):
        test_file = tmp_path / "malware.bin"
        test_file.write_text("bad stuff")
        result = quarantine_file(str(test_file))
        assert result.success
        assert not test_file.exists()
        assert (QUARANTINE_DIR / "malware.bin").exists()
        # Cleanup
        (QUARANTINE_DIR / "malware.bin").unlink(missing_ok=True)
        (QUARANTINE_DIR / "malware.bin.meta").unlink(missing_ok=True)

    def test_restore_after_quarantine(self, tmp_path):
        test_file = tmp_path / "evidence.log"
        test_file.write_text("important evidence")
        quarantine_file(str(test_file))
        assert not test_file.exists()
        result = restore_file("evidence.log")
        assert result.success
        assert test_file.exists()
        assert test_file.read_text() == "important evidence"


class TestIsolateHost:
    def test_invalid_hostname_rejected(self):
        result = isolate_host("host;evil")
        assert not result.success

    def test_canary_mode_ip(self):
        result = isolate_host("10.0.0.50", canary=True)
        assert result.success
        assert result.canary
        assert "Isolate" in result.command_preview

    def test_canary_mode_hostname(self):
        result = isolate_host("srv-web-01", canary=True)
        assert result.success
        assert result.canary
