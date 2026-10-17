#!/bin/sh
APP_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)" || exit 1
exec /usr/bin/ruby "$APP_DIR/serve.rb"
