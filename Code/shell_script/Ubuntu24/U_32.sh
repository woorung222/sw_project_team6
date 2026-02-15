#!/usr/bin/env bash
set -u

# =========================================================
# U_32 (중) 홈 디렉터리로 지정한 디렉터리의 존재 관리 | Ubuntu 24.04
# - 진단 기준: /etc/passwd 내 설정된 홈 디렉터리 존재 여부 점검
# - DB 정합성: IS_AUTO=0 (수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_32"
CATEGORY="file"
IS_AUTO=0

U_32_1=0

# 시스템 계정 포함 전체 홈 디렉터리 실재 여부 점검
while IFS=: read -r username _ _ _ _ homedir _; do
    if [ -n "$homedir" ]; then
        # 실제 디렉터리가 아닌 경우 취약 판단
        if [ ! -d "$homedir" ]; then
            U_32_1=1
            break
        fi
    fi
done < /etc/passwd

IS_VUL=$U_32_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_32_1": $U_32_1 },
    "timestamp": "$DATE"
  }
}
EOF