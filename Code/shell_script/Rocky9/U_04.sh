#!/bin/bash

# [U-04] 패스워드 파일 보호 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 쉐도우 비밀번호를 사용(shadow 파일 존재)하고, /etc/passwd의 패스워드 필드가 'x'인 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_04_1=0 
IS_VUL=0

# --- 점검 시작 ---

# 1. /etc/shadow 파일 존재 여부 확인
if [ ! -f "/etc/shadow" ]; then
    # 쉐도우 파일이 없으면 무조건 취약
    U_04_1=1
else
    # 2. /etc/passwd 파일 내 두 번째 필드가 'x'가 아닌 계정이 있는지 확인
    # awk로 구분자(:) 기준 2번째 필드가 "x"가 아닌 줄을 찾음
    NON_SHADOW_ACCOUNTS=$(awk -F: '$2 != "x" {print $1}' /etc/passwd)

    if [ -z "$NON_SHADOW_ACCOUNTS" ]; then
        # 'x'가 아닌 계정이 하나도 없으면 양호
        U_04_1=0
    else
        # 'x' 표시가 안 된 계정이 발견되면 취약
        U_04_1=1
    fi
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_04_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-04",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_04_1": $U_04_1
    },
    "timestamp": "$DATE"
  }
}
EOF