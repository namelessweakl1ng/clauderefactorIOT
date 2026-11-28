#!/usr/bin/env sh
set -eu

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

MANAGER=/opt/trapsig/sensor/scripts/manage.sh
case "${SSH_ORIGINAL_COMMAND:-}" in
  "$MANAGER status") exec "$MANAGER" status ;;
  "$MANAGER start cowrie") exec "$MANAGER" start cowrie ;;
  "$MANAGER stop cowrie") exec "$MANAGER" stop cowrie ;;
  "$MANAGER restart cowrie") exec "$MANAGER" restart cowrie ;;
  "$MANAGER start camera") exec "$MANAGER" start camera ;;
  "$MANAGER stop camera") exec "$MANAGER" stop camera ;;
  "$MANAGER restart camera") exec "$MANAGER" restart camera ;;
  "$MANAGER start router") exec "$MANAGER" start router ;;
  "$MANAGER stop router") exec "$MANAGER" stop router ;;
  "$MANAGER restart router") exec "$MANAGER" restart router ;;
  "$MANAGER start gateway") exec "$MANAGER" start gateway ;;
  "$MANAGER stop gateway") exec "$MANAGER" stop gateway ;;
  "$MANAGER restart gateway") exec "$MANAGER" restart gateway ;;
  "$MANAGER start plc") exec "$MANAGER" start plc ;;
  "$MANAGER stop plc") exec "$MANAGER" stop plc ;;
  "$MANAGER restart plc") exec "$MANAGER" restart plc ;;
  "$MANAGER start building") exec "$MANAGER" start building ;;
  "$MANAGER stop building") exec "$MANAGER" stop building ;;
  "$MANAGER restart building") exec "$MANAGER" restart building ;;
  "$MANAGER start nas") exec "$MANAGER" start nas ;;
  "$MANAGER stop nas") exec "$MANAGER" stop nas ;;
  "$MANAGER restart nas") exec "$MANAGER" restart nas ;;
  *) echo "Denied: unsupported TRAPSIG management command" >&2; exit 2 ;;
esac
