#!/bin/bash

# [U-32] 홈 디렉토리로 지정한 디렉토리의 존재 관리 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : /etc/passwd에 설정된 홈 디렉터리가 실제로 존재하지 않는 경우 취약

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_32_1=0 
IS_VUL=0

# --- 점검 시작 ---

# /etc/passwd 파일을 라인별로 읽음
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    
    # 홈 디렉터리 경로가 비어있지 않은지 확인
    if [ ! -z "$HOMEDIR" ]; then
        # 디렉터리가 실제로 존재하는지 확인 (-d)
        if [ ! -d "$HOMEDIR" ]; then
            # 디렉터리가 존재하지 않음 -> 취약
            U_32_1=1
        fi
    fi

done < /etc/passwd

# --- 최종 결과 집계 ---
IS_VUL=$U_32_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-32",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_32_1": $U_32_1
    },
    "timestamp": "$DATE"
  }
}
EOF