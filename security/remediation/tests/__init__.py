"""Tests de la remédiation. Garde-fou : aucun test ne doit faire un vrai appel réseau."""

from remediation import net


def _blocked(*args, **kwargs):
    raise AssertionError("appel réseau réel pendant les tests")


net._OPENER.open = _blocked
