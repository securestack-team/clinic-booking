# Agent IA de sécurité (triage)

L'agent lit tous les rapports SARIF de la pipeline, supprime les doublons, calcule un
**Risk Score de 0 à 10** pour chaque finding et publie un commentaire sur la Pull Request.

```
reports/*.sarif ─► normaliser ─► dédupliquer ─► triage LLM ─► Risk Score ─► commentaire de la PR
(CodeQL, Semgrep,                               (Gemini,                    reports/triage.json
 Trivy, Gitleaks...)                             optionnel)                 reports/triage.md
```

L'agent **conseille**, il ne bloque pas : le blocage du merge reste le rôle de la quality gate,
qui utilise les sévérités brutes des scanners.

Python 3.10+ et bibliothèque standard uniquement : aucune dépendance à installer ni à scanner.

## Utilisation

```bash
cd security/agent

# Sans LLM (sévérités brutes), sur les rapports d'exemple
python3 -m triage --input tests/fixtures --output /tmp/triage

# Avec le LLM
export GEMINI_API_KEY=...        # jamais dans le repo ; en CI : secret GitHub
python3 -m triage --check-llm    # teste la clé et le modèle avec un finding fictif
python3 -m triage --input ../../reports --output ../../reports --source-root ../..

# Les tests
python3 -m unittest
```

| Option | Rôle |
|---|---|
| `--input` | Dossier des rapports SARIF, sous-dossiers inclus (défaut : `reports`) |
| `--output` | Dossier où écrire `triage.json` et `triage.md` (défaut : `reports`) |
| `--source-root` | Racine du repo, pour envoyer au LLM quelques lignes autour du finding |
| `--llm none` | Désactive le LLM même si la clé existe |
| `--model` | Modèle Gemini (défaut : `gemini-3.5-flash-lite`, ou variable `AGENT_LLM_MODEL`) |
| `--comment` | Publie le résultat en commentaire de la PR (met à jour le précédent) |
| `--check-llm` | Teste l'appel au LLM puis quitte |

## Les étapes

| Étape | Fichier | Ce qu'elle fait |
|---|---|---|
| Normaliser | `triage/sarif.py` | Ramène chaque finding à : outil, règle, sévérité, CWE, fichier, ligne, message |
| Dédupliquer | `triage/dedupe.py` | Fusionne les findings qui désignent le même problème |
| Masquer | `triage/redact.py` | Remplace tout ce qui ressemble à un secret par `[MASQUÉ]` |
| Triage LLM | `triage/llm.py` | Probabilité de faux positif, exploitabilité, recommandation |
| Risk Score | `triage/scoring.py` | Applique la formule ci-dessous |
| Sorties | `triage/report.py`, `triage/github.py` | `triage.json`, commentaire Markdown |

### Déduplication

Deux findings sont fusionnés quand ils ont :

- **secret** : le même fichier et la même ligne (Gitleaks et Trivy voient le même secret) ;
- **dépendance** : la même CVE, le même paquet et le même fichier ;
- **code / configuration** : le même fichier, la même ligne et la même CWE (CodeQL et Semgrep
  sur la même injection SQL).

Le finding fusionné garde la sévérité la plus haute et la liste de tous les outils.

### Risk Score

**Risk Score = Sévérité × Exposition × Confiance**

| Facteur | Valeur | D'où elle vient |
|---|---|---|
| Sévérité | 0 à 10 | Score CVSS du scanner (`security-severity`). Sinon : critical 9.5, high 8.0, medium 5.5, low 2.0, info 0.5 |
| Exposition | 0 à 1 | Emplacement du code : `api/` 1.0 · `web/`, `mobile/`, `infra/`, `.github/` 0.9 · autre 0.7 · `security/` 0.6 · tests 0.4 · `docs/` 0.2. Avec le LLM : multipliée par (0.5 + 0.5 × exploitabilité) |
| Confiance | 0 à 1 | 1 − probabilité de faux positif (LLM), jamais sous 0.5, et jamais sous 0.8 si deux outils sont d'accord. Sans LLM : 1.0 |

Niveaux : critique ≥ 9 · élevé ≥ 7 · moyen ≥ 4 · faible < 4.

Exemples :

- Secret en dur → toujours **9.5** (le repo est public, le secret est donc exposé).
- Injection SQL dans `api/`, CVSS 8.8, LLM : faux positif 10 %, exploitabilité 80 %
  → 8.8 × (1.0 × 0.9) × 0.9 = **7.1**.
- La même faille dans `api/tests/`, sans LLM → 8.8 × 0.4 × 1.0 = **3.5**.

### Si le LLM ne répond pas

Pas de clé, erreur réseau, réponse qui n'est pas du JSON valide : après une seconde tentative,
l'agent continue avec les **sévérités brutes** (Confiance = 1.0) et des recommandations par
défaut. Le commentaire l'indique. L'agent sort toujours en code 0.

## Sécurité du LLM

| Risque (OWASP Top 10 for LLM Applications) | Contrôle |
|---|---|
| LLM02 Fuite de données sensibles | Les findings de type secret (Gitleaks, secrets Trivy, CWE-798) ne sont **jamais** envoyés. Messages et extraits de code passent par `redact()`. Le message d'un scanner de secrets n'est même pas gardé |
| LLM01 Prompt injection | Le contenu analysé est présenté au LLM comme une donnée. Surtout : le LLM ne peut que **baisser** un score, au maximum d'un facteur 4, il ne peut supprimer aucun finding, et la quality gate ne dépend pas de lui |
| LLM05 Sortie mal gérée | Réponse validée par `schemas/llm-response.schema.json`, élément par élément. Rien n'est exécuté. Dans le commentaire, tout texte non fiable est échappé (Markdown, HTML, liens, mentions) |
| LLM06 Trop de pouvoir | L'agent lit des rapports et écrit un commentaire, rien d'autre. Token : `pull-requests: write` seulement |
| LLM10 Consommation illimitée | 45 findings envoyés au maximum, par lots de 15 ; textes tronqués |

Autres protections : un chemin de fichier venu d'un SARIF ne peut pas faire lire un fichier hors
du repo ; la clé d'API part dans un en-tête (pas dans l'URL) et les redirections HTTP sont
refusées ; les logs ne peuvent pas injecter de commande GitHub Actions.

## `reports/triage.json` (entrée de la remédiation automatique)

Le format est décrit par [`schemas/triage.schema.json`](schemas/triage.schema.json). Les findings
sont triés du Risk Score le plus haut au plus bas.

```json
{
  "id": "a90dea08ce76",
  "category": "dependency",
  "severity": "high",
  "risk_score": 7.5,
  "risk_level": "high",
  "tools": ["Trivy"],
  "rules": ["CVE-2024-21907"],
  "file": "api/packages.lock.json",
  "line": 5,
  "package": { "name": "Newtonsoft.Json", "installed_version": "12.0.1", "fixed_version": "13.0.1", "advisory": "CVE-2024-21907" },
  "recommendation": "Mettre à jour Newtonsoft.Json vers la version 13.0.1."
}
```

- `id` : stable d'une exécution à l'autre, utilisable pour la branche `autofix/<id>`.
- `category` : `secret`, `dependency`, `config` ou `code`.
- `package` : rempli pour les dépendances vulnérables (remédiation v1).
- `severity` est la sévérité brute du scanner ; `risk_score` est la priorité calculée.

## Le LLM : Gemini

GitHub Models a été arrêté le 30 juillet 2026
([documentation GitHub](https://docs.github.com/en/rest/models/inference)) : il ne reste que
Gemini parmi les deux options prévues. La clé s'obtient sur Google AI Studio et se range dans le secret GitHub
`GEMINI_API_KEY`.

## Intégration dans la pipeline

Job à ajouter dans `.github/workflows/security.yml` (module CI/CD) :

```yaml
  ai-triage:
    name: AI Security Agent
    needs: [gitleaks, trivy, codeql]
    # always() : l'agent doit aussi tourner quand un scanner a fait échouer la quality gate
    if: always() && github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          pattern: sarif-*
          path: reports
      - name: Tests de l'agent
        working-directory: security/agent
        run: python3 -m unittest
      - name: Triage
        env:
          GITHUB_TOKEN: ${{ github.token }}
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          PYTHONPATH: security/agent
        run: python3 -m triage --input reports --output reports --comment
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: triage
          path: |
            reports/triage.json
            reports/triage.md
```

À savoir :

- Sur une PR de Dependabot ou d'un fork, GitHub ne donne ni le secret ni le droit d'écrire :
  l'agent tourne sans LLM et n'arrive pas à commenter, sans faire échouer le job. Le résultat
  reste visible dans le résumé du job et dans l'artefact.
- Ajouter `python` aux langages CodeQL pour que le code de l'agent soit lui aussi scanné.

## Limites connues

- L'appel réel à Gemini n'a pas encore été testé (pas de clé) : lancer `--check-llm` dès que la
  clé existe. Les tests utilisent un LLM simulé.
- Vérifié sur de vrais rapports : les findings Gitleaks et les secrets Trivy, ainsi que
  l'emplacement des règles CodeQL. Les autres exemples de `tests/fixtures` (résultats CodeQL,
  Semgrep, vulnérabilités et configuration Trivy) suivent le format documenté des outils : à
  revérifier sur les premiers vrais findings de la pipeline.
