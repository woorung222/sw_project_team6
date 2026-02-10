#!/bin/bash

# [U-26] /dev에 존재하지 않는 device 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /dev 디렉터리 내에 불필요한 일반 파일(Regular File)이 존재하지 않으면 양호
# 주의 : /dev/shm, /dev/mqueue 등 시스템이 정상적으로 사용하는 경로는 제외

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_26_1=0 
IS_VUL=0
VULN_DETAILS=""

# --- 점검 시작 ---

# find 명령어 설명:
# /dev : 검색 시작 위치
# -path "/dev/shm" -prune : /dev/shm 디렉터리는 검색하지 않음 (공유 메모리 사용)
# -o -path "/dev/mqueue" -prune : /dev/mqueue 검색 제외
# -o -path "/dev/.udev" -prune : udev 관련 디렉터리 제외 (존재할 경우)
# -o -type f : 위 제외 경로가 아닌 곳에서 '일반 파일' 검색
# -print : 발견 시 경로 출력

# Rocky 9 등 최신 시스템 환경을 고려하여 정상적인 런타임 디렉터리 제외
FOUND_FILES=$(find /dev \
    \( -path "/dev/shm" -o -path "/dev/mqueue" -o -path "/dev/.udev" -o -path "/dev/fd" \) -prune \
    -o -type f -print 2>/dev/null)

if [ -z "$FOUND_FILES" ]; then
    # 발견된 일반 파일이 없음 (양호)
    U_26_1=0
else
    # /dev 내에 의심스러운 일반 파일 존재 (취약)
    U_26_1=1
    # 디버깅용: 발견된 파일 목록을 로그로 남길 수 있음
    # echo "$FOUND_FILES"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_26_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-26",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_26_1": $U_26_1
    },
    "timestamp": "$DATE"
  }
}
EOF