#!/usr/bin/env bash
set -u

# =========================================================
# U_26 (상) /dev에 존재하지 않는 device 파일 점검 | Ubuntu 24.04
# - 진단 기준: /dev 내 일반 파일 존재 여부 점검 (예외 디렉터리 제외)
# - DB 정합성: IS_AUTO=0 (시스템 영향으로 인한 수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_26"
CATEGORY="file"
IS_AUTO=0

U_26_1=0

# 시스템 정상 사용 경로(shm, mqueue, .udev) 제외하고 일반 파일 탐색
if find /dev \( -path "/dev/shm" -prune -o -path "/dev/mqueue" -prune -o -path "/dev/.udev" -prune \) -o -type f -print | grep -q .; then
    U_26_1=1
fi

IS_VUL=$U_26_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_26_1": $U_26_1 },
    "timestamp": "$DATE"
  }
}
EOF