#!/usr/bin/env bash
set -u

# =========================================================
# U_22 (상) /etc/services 파일 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 소유자 root, 권한 644 이하
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_22"
CATEGORY="file"
IS_AUTO=1

U_22_1=0

if [ -f "/etc/services" ]; then
    OWNER=$(stat -c "%U" "/etc/services")
    PERM=$(stat -c "%a" "/etc/services")
    
    if [[ "$OWNER" =~ ^(root|bin|sys)$ ]] && [ "$PERM" -le 644 ]; then
        U_22_1=0
    else
        U_22_1=1
    fi
fi

IS_VUL=$U_22_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_22_1": $U_22_1 },
    "timestamp": "$DATE"
  }
}
EOF