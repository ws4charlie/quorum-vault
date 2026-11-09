# Sourced by the scripts that need the SoftHSM PINs. qv_load_pins sets QV_HSM_PIN (and QV_HSM_SO_PIN) from the environment, else from ./.env
# (written by `make dev-env`); with no value it stops with a message that names `make dev-env`. There is no default.
qv_env_value() { # qv_env_value <name>: the value of <name> in .env, empty if none
  [ -f "$QV_LIB_ROOT/.env" ] || return 0
  sed -n "s/^$1=//p" "$QV_LIB_ROOT/.env" | tail -n 1
}

qv_load_pins() { # qv_load_pins [--so]
  QV_LIB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [ -z "${QV_HSM_PIN:-}" ]; then QV_HSM_PIN="$(qv_env_value QV_HSM_PIN)"; fi
  if [ -z "${QV_HSM_PIN:-}" ]; then
    echo "QV_HSM_PIN is not set: run \`make dev-env\` (it writes random PINs to .env)" >&2
    return 1
  fi
  export QV_HSM_PIN
  if [ "${1:-}" = --so ]; then
    if [ -z "${QV_HSM_SO_PIN:-}" ]; then QV_HSM_SO_PIN="$(qv_env_value QV_HSM_SO_PIN)"; fi
    if [ -z "${QV_HSM_SO_PIN:-}" ]; then
      echo "QV_HSM_SO_PIN is not set: run \`make dev-env\` (it writes random PINs to .env)" >&2
      return 1
    fi
    export QV_HSM_SO_PIN
  fi
}
