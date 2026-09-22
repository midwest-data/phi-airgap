"""pytest/CI shim — the suite ships as `phi_airgap.selftest` (`phi-airgap selftest`)."""

from phi_airgap import selftest


def test_airgap():
    assert selftest.main() == 0


if __name__ == "__main__":
    raise SystemExit(selftest.main())
