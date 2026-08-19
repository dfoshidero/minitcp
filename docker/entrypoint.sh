#!/bin/bash
if [ $# -eq 0 ]; then
  minitcp --help
  exec bash
fi
exec minitcp "$@"
