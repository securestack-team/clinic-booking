"""Tests de l'agent. Garde-fou : aucun test ne doit faire un vrai appel réseau."""

from triage import net


def _blocked(*args, **kwargs):
    raise AssertionError("appel réseau réel pendant les tests")


net._OPENER.open = _blocked
