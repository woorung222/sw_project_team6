#!/usr/bin/env bash
set -u

# =========================================================
# U_04 (상) 패스워드 파일 보호 | Ubuntu 24.04
# - 진단 기준: 쉐도우 패스워드 사용 여부 (Rocky/Ansible 기준 통일)
# - 기존 권한/소유자 점검 로직 제거 (기준에 맞춤)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_04"
CATEGORY="account"
IS_AUTO=1

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_04_1=0 

# -------------------------
# 1) 쉐도우 사용 여부 점검
# - /etc/shadow 파일 존재 여부
# - /etc/passwd 2번째 필드 'x' 여부
# -------------------------
SHADOW_FILE="/etc/shadow"
PASSWD_FILE="/etc/passwd"

if [ ! -f "$SHADOW_FILE" ]; then
  # 쉐도우 파일 없으면 취약
  FLAG_U_04_1=1
else
  # 쉐도우 파일은 있는데, passwd 파일에 평문 비번이 있는지 확인
  # 2번째 필드가 'x'가 아닌 계정이 하나라도 있으면 취약
  if awk -F: '$2 != "x" {print $1}' "$PASSWD_FILE" 2>/dev/null | grep -q '.'; then
    FLAG_U_04_1=1
  else
    FLAG_U_04_1=0
  fi
fi

# -------------------------
# 2) Output (JSON)
# -------------------------
IS_VUL=$FLAG_U_04_1

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
      "U_04_1": $FLAG_U_04_1
    },
    "timestamp": "$DATE"
  }
}
EOF