#!/bin/bash

# [U-33] 숨겨진 파일 및 디렉토리 검색 및 제거 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /tmp, /var/tmp, /dev 등 주요 경로에 불필요한 숨겨진 파일 발견 시 취약
# DB 정합성 : IS_AUTO=0 (오탐 및 파일 삭제 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_33_1=0 
IS_VUL=0
IS_AUTO=0 

# 점검 대상 디렉터리 (악성 파일 은닉 상습 구간)
CHECK_DIRS="/tmp /var/tmp /dev"

# 점검 로직
# 정상적인 시스템 파일(.udev, .blkid 등)은 제외하고 숨겨진 파일(name ".*") 검색
FOUND_FILES=$(find $CHECK_DIRS -maxdepth 2 \( -path "/dev/.udev" -prune -o -path "/dev/.blkid" -prune \) -o -name ".*" ! -name "." ! -name ".." -print 2>/dev/null)

if [ -n "$FOUND_FILES" ]; then
    U_33_1=1
fi

IS_VUL=$U_33_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-33",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_33_1": $U_33_1 },
    "timestamp": "$DATE"
  }
}
EOF