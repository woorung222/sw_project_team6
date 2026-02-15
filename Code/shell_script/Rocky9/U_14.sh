#!/bin/bash

# [U-14] root 홈, 패스 디렉터리 권한 및 패스 설정
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : PATH 환경변수의 맨 앞이나 중간에 "." 또는 "::"이 포함되지 않은 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_14_1=0 
IS_VUL=0
IS_AUTO=0 

# --- [U_14_1] 현재 PATH 환경변수 점검 ---
# 기준: 맨 앞(.:), 중간(:.:), 빈 경로(::) 확인
if echo "$PATH" | grep -qE "^\.:|^::|:.:|::$"; then
    # 취약한 패턴 발견
    U_14_1=1
else
    U_14_1=0
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_14_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-14",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": {
      "U_14_1": $U_14_1
    },
    "timestamp": "$DATE"
  }
}
EOF