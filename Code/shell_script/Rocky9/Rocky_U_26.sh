#!/bin/bash

# [U-26] /dev에 존재하지 않는 device 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /dev 디렉터리 내에 불필요한 일반 파일(Regular File)이 존재하지 않으면 양호
# DB 정합성 : IS_AUTO=0 (시스템 디바이스 영향으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_26_1=0 
IS_VUL=0
IS_AUTO=0 

# 점검 시작
# 정상적인 시스템 런타임 파일(shm, mqueue 등)은 제외하고 일반 파일(-type f) 검색
FOUND_FILES=$(find /dev \
    \( -path "/dev/shm" -prune -o -path "/dev/mqueue" -prune -o -path "/dev/.udev" -prune \) \
    -o -type f -print 2>/dev/null)

if [ -n "$FOUND_FILES" ]; then
    U_26_1=1
fi

IS_VUL=$U_26_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-26",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_26_1": $U_26_1 },
    "timestamp": "$DATE"
  }
}
EOF