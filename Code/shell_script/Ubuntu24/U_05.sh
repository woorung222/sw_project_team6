#!/usr/bin/env bash
set -u

# =========================================================
# U_05 (상) root 이외의 UID가 ‘0’ 금지 점검 | Ubuntu 24.04
# - 진단 기준: root 계정 외에 UID가 0인 계정이 존재하지 않으면 양호
# - DB/Rocky 기준과 일치시킴 (기존 PATH 점검 로직 제거)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_05"
CATEGORY="account"
IS_AUTO=0  # 중요: 계정 삭제는 위험하므로 수동 조치(0)

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_05_1=0

# -------------------------
# 1) UID 0인 계정 점검
# - /etc/passwd의 3번째 필드(UID)가 0이면서
# - 1번째 필드(계정명)가 'root'가 아닌 경우 탐지
# -------------------------
UID_ZERO_ACCOUNTS=""
if [ -f /etc/passwd ]; then
  UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
fi

if [ -n "$UID_ZERO_ACCOUNTS" ]; then
  # root가 아닌데 UID 0인 계정이 존재함 -> 취약
  FLAG_U_05_1=1
else
  # 발견되지 않음 -> 양호
  FLAG_U_05_1=0
fi

# -------------------------
# 2) Output (JSON)
# -------------------------
IS_VUL=$FLAG_U_05_1

cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_05_1": $FLAG_U_05_1
    },
    "timestamp": "$DATE"
  }
}
EOF