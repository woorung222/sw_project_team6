#!/usr/bin/env bash
set -u

# =========================================================
# U_05 (상) root 이외의 UID가 ‘0’ 금지 점검 | Ubuntu 24.04
# - (DB 기준) root 계정 외에 UID가 0인 계정이 존재하지 않으면 양호
# - 팀 조건: flag(0/1) 명확 판별, VULN_STATUS는 flag로만 산출
# - Ubuntu(Debian) 반영: flag 1개 (U_05_1)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_05"
CATEGORY="account"
IS_AUTO=0  # 중요: DB 기준에 맞춰 자동 조치 불가(0)로 설정

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_05_1=0  # 기본은 양호로 시작

# -------------------------
# 1) UID 0인 계정 점검
# - /etc/passwd의 3번째 필드(UID)가 0이면서, 
# - 1번째 필드(계정명)가 'root'가 아닌 경우 탐지
# -------------------------

# 결과가 있으면 변수에 저장 (공백/줄바꿈 포함될 수 있음)
UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

if [ -n "$UID_ZERO_ACCOUNTS" ]; then
  # root가 아닌데 UID 0인 계정이 존재함 -> 취약
  FLAG_U_05_1=1
else
  # 발견되지 않음 -> 양호
  FLAG_U_05_1=0
fi

# -------------------------
# VULN_STATUS (flag로만 산출)
# -------------------------
if [ "$FLAG_U_05_1" -eq 1 ]; then
  IS_VUL=1
else
  IS_VUL=0
fi

# -------------------------
# Output (JSON)
# -------------------------
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