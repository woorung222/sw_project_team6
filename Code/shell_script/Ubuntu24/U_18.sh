#!/usr/bin/env bash
set -u

# =========================================================
# U_18 (상) /etc/shadow 파일 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 소유자 root, 권한 400 이하
# - DB 정합성: IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_18"
CATEGORY="file"
IS_AUTO=1

FLAG_U_18_1=0
TARGET_FILE="/etc/shadow"

if [ -f "$TARGET_FILE" ]; then
    OWNER=$(stat -c "%U" "$TARGET_FILE")
    PERM=$(stat -c "%a" "$TARGET_FILE")

    # 진단 로직 통일
    if [ "$OWNER" = "root" ] && [ "$PERM" -le 400 ]; then
        FLAG_U_18_1=0
    else
        FLAG_U_18_1=1
    fi
else
    FLAG_U_18_1=1
fi

IS_VUL=$FLAG_U_18_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_18_1": $FLAG_U_18_1 },
    "timestamp": "$DATE"
  }
}
EOF