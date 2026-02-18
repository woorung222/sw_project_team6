#!/usr/bin/env bash
set -u

# =========================================================
# U_25 (상) world writable 파일 점검 | Ubuntu 24.04
# - 진단 기준: 불필요한 world writable 파일 존재 여부 점검
# - DB 정합성: IS_AUTO=0 (서비스 영향으로 인한 수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_25"
CATEGORY="file"
IS_AUTO=0

U_25_1=0

# 하나라도 발견되면 즉시 취약 처리 (속도 최적화 및 로컬 파티션 한정)
if find / -xdev -type f -perm -0002 -print -quit 2>/dev/null | grep -q .; then
    U_25_1=1
fi

IS_VUL=$U_25_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_24_1": $U_25_1 },
    "timestamp": "$DATE"
  }
}
EOF