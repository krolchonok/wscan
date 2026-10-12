#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BINARY="$SCRIPT_DIR/wscan"
if [ ! -f "$BINARY" ] || [ ! -x "$BINARY" ]; then
    echo "Нет исполняемого wscan рядом со скриптом. Распакуйте весь архив релиза." >&2
    exit 1
fi
CALLER_CONFIG=${XDG_CONFIG_HOME:-}
if [ -z "$CALLER_CONFIG" ]; then
    CALLER_HOME=${HOME:-}
    # sudo ./start.sh: recover the original user's home, not /root.
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
        CALLER_HOME=$(getent passwd "$SUDO_USER" | awk -F: '{print $6}')
    fi
    if [ -z "$CALLER_HOME" ]; then
        echo "Не удалось определить каталог пользователя; укажи XDG_CONFIG_HOME." >&2
        exit 1
    fi
    CALLER_CONFIG="$CALLER_HOME/.config"
fi
case "$CALLER_CONFIG" in
    /*) ;;
    *) echo "XDG_CONFIG_HOME должен быть абсолютным путём." >&2; exit 1 ;;
esac
# Compute the path before sudo changes HOME and filters the environment.
set -- env "XDG_CONFIG_HOME=$CALLER_CONFIG" "${BINARY}" "$@"
if [ -n "${WSCAN_LIBRARY_DIR:-}" ]; then
    shift
    set -- env "WSCAN_LIBRARY_DIR=$WSCAN_LIBRARY_DIR" "$@"
fi
cd "$SCRIPT_DIR"
if [ "$(id -u)" -eq 0 ]; then
    exec "$@"
fi
if ! command -v sudo >/dev/null 2>&1; then
    echo "Для запуска от root нужен sudo." >&2
    exit 1
fi
exec sudo -- "$@"
