#!/bin/bash

# [U-25] world writable 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 불필요한 world writable 파일(other에 쓰기 권한이 있는 파일)이 존재하면 취약
# 주의 : 대용량 파일 시스템의 경우 점검 시간이 다소 소요될 수 있습니다.

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_25_1=0 
IS_VUL=0

# --- 점검 시작 ---

# find 명령어 옵션 설명:
# / : 루트 디렉터리부터 검색
# -xdev : 현재 파일 시스템만 검색 (proc, sys, devpts 등 제외하여 속도 향상 및 오류 방지)
# -type f : 일반 파일만 검색 (디렉터리, 소켓 등 제외)
# -perm -0002 : Other(일반 사용자)에 Write 권한(2)이 포함된 파일 검색
# -print -quit : 하나라도 발견되면 경로를 출력하고 즉시 종료 (빠른 진단용)
# 2>/dev/null : 'Permission denied' 등의 에러 메시지 무시

FOUND_FILE=$(find / -xdev -type f -perm -0002 -print -quit 2>/dev/null)

if [ -z "$FOUND_FILE" ]; then
    # 발견된 파일이 없음 (양호)
    U_25_1=0
else
    # World Writable 파일이 존재함 (취약)
    U_25_1=1
    # 참고: 전체 목록을 보고 싶다면 스크립트 종료 후 별도로 find 명령어를 실행해야 함
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_25_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-25",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_25_1": $U_25_1
    },
    "timestamp": "$DATE"
  }
}
EOF