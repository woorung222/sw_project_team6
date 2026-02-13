#!/usr/bin/env bash
set -u

# =========================================================
# U_30 (중) UMASK 설정 관리 | Ubuntu 24.04
# - 진단 기준: UMASK 값 022 이상 설정 여부
# - DB 정합성: IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_30"
CATEGORY="file"
IS_AUTO=1

U_30_1=0 # /etc/profile
U_30_2=0 # /etc/login.defs

# 1) /etc/profile 점검
if [ -f "/etc/profile" ]; then
    P_VAL=$(grep -i "^[[:space:]]*umask" /etc/profile | tail -n 1 | awk '{print $2}')
    # 값이 없거나 022보다 작으면 취약
    if [ -z "$P_VAL" ] || [ "$P_VAL" -lt 22 ]; then
        U_30_1=1
    fi
fi

# 2) /etc/login.defs 점검
if [ -f "/etc/login.defs" ]; then
    L_VAL=$(grep -i "^[[:space:]]*UMASK" /etc/login.defs | grep -v "^#" | tail -n 1 | awk '{print $2}')
    if [ -z "$L_VAL" ] || [ "$L_VAL" -lt 22 ]; then
        U_30_2=1
    fi
fi

IS_VUL=0
[ "$U_30_1" -eq 1 ] || [ "$U_30_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_30_1": $U_30_1, "U_30_2": $U_30_2 },
    "timestamp": "$DATE"
  }
}
EOF