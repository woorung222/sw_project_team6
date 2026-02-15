#!/bin/bash

# [U-29] hosts.lpd 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 파일이 없거나, 소유자가 root이고 권한이 600 이하인 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_29_1=0 
IS_VUL=0

# --- 점검 시작 ---
TARGET_FILE="/etc/hosts.lpd"

if [ ! -f "$TARGET_FILE" ]; then
    # 1. 파일이 존재하지 않음 (양호 - 권장)
    U_29_1=0
else
    # 파일이 존재하는 경우 속성 점검
    OWNER=$(stat -c "%U" "$TARGET_FILE")
    PERM=$(stat -c "%a" "$TARGET_FILE")

    # 진단 로직
    # 조건 1: 소유자가 root 인가?
    # 조건 2: 권한이 600 이하인가? (600, 400 등은 OK / 644, 666 등은 취약)
    if [ "$OWNER" == "root" ] && [ "$PERM" -le 600 ]; then
        U_29_1=0
    else
        # 소유자가 root가 아니거나, 권한이 600을 초과함
        U_29_1=1
    fi
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_29_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-29",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_29_1": $U_29_1
    },
    "timestamp": "$DATE"
  }
}
EOF