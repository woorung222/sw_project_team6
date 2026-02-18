#!/usr/bin/env bash
set -u

# =========================================================
# U_33 (중) 숨겨진 파일 및 디렉토리 검색 및 제거 | Ubuntu 24.04
# - 진단 기준 : 주요 의심 경로(/tmp, /dev 등) 내 숨겨진 파일 존재 여부 점검
# - DB 정합성 : IS_AUTO=0 (수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_33"
CATEGORY="file"
IS_AUTO=0

U_33_1=0

# 주요 의심 경로에서 시스템 예외 파일을 제외하고 숨겨진 파일 탐색
if find /tmp /var/tmp /dev -maxdepth 2 \( -path "/dev/.udev" -prune -o -path "/dev/.blkid" -prune \) -o -name ".*" ! -name "." ! -name ".." -print | grep -q .; then
    U_33_1=1
fi

IS_VUL=$U_33_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_33_1": $U_33_1 },
    "timestamp": "$DATE"
  }
}
EOF