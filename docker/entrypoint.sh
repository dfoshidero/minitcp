#!/bin/bash
if [ $# -eq 0 ]; then
  exec bash --rcfile /usr/local/share/minitcp-shell.sh
fi
exec minitcp "$@"
