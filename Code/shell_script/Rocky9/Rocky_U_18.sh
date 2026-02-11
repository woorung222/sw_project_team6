#!/bin/bash

# [U-18] /etc/shadow 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root이고, 권한이 400 이하인 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_18_1=0 
IS_VUL=0

# --- 점검 시작 ---
TARGET_FILE="/etc/shadow"

if [ -f "$TARGET_FILE" ]; then
    # 1. 소유자 확인
    OWNER=$(stat -c "%U" "$TARGET_FILE")
    
    # 2. 권한 확인 (숫자 형태)
    PERM=$(stat -c "%a" "$TARGET_FILE")

    # 진단 로직
    # 조건 1: 소유자가 root 인가?
    # 조건 2: 권한이 400 이하인가? (000, 400은 OK / 600, 640은 취약)
    if [ "$OWNER" == "root" ] && [ "$PERM" -le 400 ]; then
        U_18_1=0
    else
        # 소유자가 다르거나, 권한이 400을 초과함 (예: 600)
        U_18_1=1
    fi
else
    # 파일이 없는 경우 (매우 심각한 오류이나 취약으로 처리)
    U_18_1=1
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_18_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-18",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_18_1": $U_18_1
    },
    "timestamp": "$DATE"
  }
}
EOF