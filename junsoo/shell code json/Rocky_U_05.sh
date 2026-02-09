#!/bin/bash

# [U-05] root 이외의 UID가 ‘0’ 금지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : root 계정 외에 UID가 0인 계정이 존재하지 않으면 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_05_1=0 
IS_VUL=0

# --- 점검 시작 ---

# /etc/passwd 파일에서 UID(3번째 필드)가 0인 행을 찾음
# 그리고 그 행의 계정명(1번째 필드)이 'root'가 아닌 경우를 추출
UID_ZERO_ACCOUNTS=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)

if [ -z "$UID_ZERO_ACCOUNTS" ]; then
    # root 외에 UID 0인 계정이 없음 (양호)
    U_05_1=0
else
    # root 외에 UID 0인 계정이 존재함 (취약)
    # 예: toor, admin 등
    U_05_1=1
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_05_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-05",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "account",
    "flag": {
      "U_05_1": $U_05_1
    },
    "timestamp": "$DATE"
  }
}
EOF