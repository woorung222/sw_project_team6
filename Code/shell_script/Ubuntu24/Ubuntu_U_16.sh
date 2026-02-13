#!/usr/bin/env bash
set -u

# =========================================================
# U_16 (상) /etc/passwd 파일 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 소유자가 root이고, 권한이 644 이하인 경우 양호
# - DB 정합성: IS_AUTO=0 (수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_16"
CATEGORY="file"
IS_AUTO=0

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_16_1=0

TARGET_FILE="/etc/passwd"

# -------------------------
# 1) 파일 존재 여부 및 소유자/권한 점검
# -------------------------
if [ -f "$TARGET_FILE" ]; then
    # 소유자 및 권한(숫자) 추출
    OWNER=$(stat -c "%U" "$TARGET_FILE")
    PERM=$(stat -c "%a" "$TARGET_FILE")

    # 진단 로직: 소유자 root && 권한 644 이하
    if [ "$OWNER" = "root" ] && [ "$PERM" -le 644 ]; then
        FLAG_U_16_1=0
    else
        FLAG_U_16_1=1
    fi
else
    # 파일이 없는 경우 (이론적으로 불가능하나 보안상 양호 처리하지 않음)
    FLAG_U_16_1=1
fi

# -------------------------
# 2) Output (JSON)
# -------------------------
IS_VUL=$FLAG_U_16_1

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
      "U_16_1": $FLAG_U_16_1
    },
    "timestamp": "$DATE"
  }
}
EOF