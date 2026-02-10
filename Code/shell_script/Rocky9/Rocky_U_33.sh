#!/bin/bash

# [U-33] 숨겨진 파일 및 디렉토리 검색 및 제거 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /tmp, /var/tmp, /dev 등 고위험 디렉터리에 불필요한 숨겨진 파일이 발견되면 취약
#            (전체 경로 검색은 정상 파일이 너무 많아 오탐이 심하므로 주요 의심 경로만 진단)

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_33_1=0 
IS_VUL=0

# --- 점검 시작 ---

# 점검 대상 디렉터리 (악성 파일 은닉 상습 구간)
CHECK_DIRS="/tmp /var/tmp /dev /run/shm"

# find 옵션:
# -name ".*" : 숨겨진 파일/디렉터리 검색
# ! -name "." ! -name ".." : 현재(.)와 상위(..) 디렉터리 제외
# ! -path "/dev/.udev" ... : 시스템 정상 숨김 파일 제외 (필요 시 추가)
# 2>/dev/null : 접근 에러 무시

# Rocky 9 특성상 /dev/.udev 등은 제외 필요
EXCLUDE_PATHS="-o -path /dev/.udev -o -path /dev/.blkid"

FOUND_FILES=$(find $CHECK_DIRS -name ".*" ! -name "." ! -name ".." 2>/dev/null | grep -vE "/dev/\.udev|/dev/\.blkid")

if [ -z "$FOUND_FILES" ]; then
    # 의심 경로에 숨겨진 파일 없음 (양호)
    U_33_1=0
else
    # 숨겨진 파일 발견 (취약 - 관리자 확인 필요)
    U_33_1=1
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_33_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-33",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_33_1": $U_33_1
    },
    "timestamp": "$DATE"
  }
}
EOF