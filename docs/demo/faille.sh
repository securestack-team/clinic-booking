#!/usr/bin/env bash
# Démo de détection : pousser une faille volontaire, voir la pipeline la bloquer, corriger.
#
#   faille.sh bloque        fausse PAIRE de clés AWS  -> push refusé par la push protection
#   faille.sh rouge         fausse clé seule + PR     -> pipeline rouge (Gitleaks, Trivy)
#   faille.sh suppression   clé retirée dans un nouveau commit -> Gitleaks encore rouge
#   faille.sh vert          historique réécrit        -> pipeline verte
#   faille.sh nettoyer      ferme la PR et supprime la branche
#
# À lancer depuis le repo, avec une copie du script placée hors du repo :
#   cp docs/demo/faille.sh /tmp/faille.sh && /tmp/faille.sh bloque
#
# Les clés sont FAUSSES : elles sont fabriquées ici et ne donnent accès à rien.

set -euo pipefail

BRANCH="${DEMO_BRANCH:-demo/faille}"
FILE="api/appsettings.json"

# La clé est assemblée en deux morceaux : écrite d'un seul tenant, elle ferait échouer
# Gitleaks sur ce script lui-même.
KEY_ID="AKIA""Q7ZK2M5XWB4LNT3H"

main() {
  cd "$(git rev-parse --show-toplevel)"
  case "${1:-}" in
    bloque) step_bloque ;;
    rouge) step_rouge ;;
    suppression) step_suppression ;;
    vert) step_vert ;;
    nettoyer) step_nettoyer ;;
    *) sed -n '2,12p' "$0"; exit 1 ;;
  esac
}

write_settings() { # $1 = lignes de clés à insérer (peut être vide)
  mkdir -p "$(dirname "$FILE")"
  {
    printf '{\n  "Storage": {\n    "BucketName": "clinic-booking-demo"'
    [ -n "$1" ] && printf ',\n%s' "$1"
    printf '\n  }\n}\n'
  } > "$FILE"
}

commit() { # $1 = message, le reste = options de git commit
  local message="$1"; shift
  git add "$FILE"
  if ! git commit --quiet "$@" -m "$message"; then
    echo ">>> Le hook pre-commit (Gitleaks) a bloqué le commit : c'est la première barrière. Capture d'écran !"
    echo ">>> Pour la suite de la démo, on fait comme un développeur qui n'a pas installé le hook."
    git commit --quiet --no-verify "$@" -m "$message"
  fi
}

start_branch() {
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Des modifications ne sont pas commitées : range-les avant la démo." >&2; exit 1
  fi
  git fetch --quiet origin main
  git switch --quiet -C "$BRANCH" origin/main
}

step_bloque() {
  start_branch
  local secret_key
  secret_key="$(openssl rand -base64 48 | tr -d '\n=' | cut -c1-40)"
  write_settings "$(printf '    "AccessKeyId": "%s",\n    "SecretAccessKey": "%s"' "$KEY_ID" "$secret_key")"
  commit "chore: add storage settings with a hard-coded fake key (demo, do not merge)"
  echo ">>> git push : GitHub doit REFUSER (push protection)."
  if git push -u origin "$BRANCH"; then
    echo ">>> Le push est passé : la push protection n'a pas reconnu la paire. Lance « rouge » directement."
  else
    echo ">>> Push refusé : capture d'écran, puis lance « rouge »."
  fi
}

step_rouge() {
  [ "$(git branch --show-current)" = "$BRANCH" ] || start_branch
  write_settings "$(printf '    "AccessKeyId": "%s"' "$KEY_ID")"
  if [ -n "$(git log --format=%h origin/main..HEAD)" ]; then
    commit "chore: add storage settings with a hard-coded fake key (demo, do not merge)" --amend
  else
    commit "chore: add storage settings with a hard-coded fake key (demo, do not merge)"
  fi
  git push -u --force-with-lease origin "$BRANCH"
  if command -v gh >/dev/null && gh pr create --base main --head "$BRANCH" \
      --title "demo: faille volontaire (secret en dur), ne pas merger" \
      --body "Démo de détection : fausse clé au format AWS dans \`$FILE\`. Pipeline rouge attendue, puis correction. **Ne pas merger.**"; then
    echo ">>> PR ouverte. Attendre ~1 min : Gitleaks et Trivy doivent être ROUGES."
  else
    echo ">>> Ouvre la PR à la main pour la branche $BRANCH (ou elle existe déjà)."
  fi
}

step_suppression() {
  write_settings ""
  commit "fix: remove hard-coded key from storage settings"
  git push origin "$BRANCH"
  echo ">>> Attendre ~1 min : Trivy VERT, mais Gitleaks encore ROUGE (la clé est dans l'historique)."
}

step_vert() {
  write_settings ""
  git add "$FILE"
  git reset --quiet --soft origin/main
  commit "chore: add storage settings without any secret"
  git push --force-with-lease origin "$BRANCH"
  echo ">>> Attendre ~1 min : tout doit être VERT."
}

step_nettoyer() {
  command -v gh >/dev/null && gh pr close "$BRANCH" --comment "Démo terminée, PR fermée sans merge." || true
  git push origin --delete "$BRANCH" || true
  git switch --quiet main
  git branch -D "$BRANCH" || true
  echo ">>> Branche de démo supprimée."
}

main "$@"
