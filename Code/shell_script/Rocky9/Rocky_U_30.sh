#!/bin/bash

# [U-30] 시스템 UMASK 값이 022 이상 설정 여부 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : UMASK 값이 022 이상(022, 027 등)으로 설정된 경우 양호
#            (숫자가 높을수록 더 제한적인 권한을 의미함. 예: 022=755/644, 002=775/664)

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_30_1=0 # /etc/profile 점검
U_30_2=0 # /etc/login.defs 점검
IS_VUL=0

# --- [U_30_1] /etc/profile 파일 점검 ---
# /etc/profile 내 umask 설정 확인
# (보통 맨 마지막에 설정된 값이 유효하므로 tail로 마지막 값 확인)

PROFILE="/etc/profile"
PROFILE_UMASK=""

if [ -f "$PROFILE" ]; then
    # 주석 제외, umask 문자열을 찾아 값 추출 (대소문자 무시)
    # 예: umask 022 -> 022 추출
    PROFILE_UMASK=$(grep -i "^[[:space:]]*umask" "$PROFILE" | grep -v "^#" | tail -n 1 | awk '{print $2}')

    if [ -z "$PROFILE_UMASK" ]; then
        # 설정이 없으면 취약으로 간주 (명시적 설정 권고)
        U_30_1=1
    else
        # 값 비교 (022 이상인지)
        # Bash에서 0으로 시작하는 숫자는 8진수로 인식될 수 있으나, 비교 연산에서는 정수로 처리됨
        # 022(18) vs 002(2) -> 18 >= 2 (True)
        # 안전한 비교를 위해 10진수로 변환하여 비교하거나, 문자열 비교 수행
        
        # 022보다 작으면(002 등) 취약
        if [ "$PROFILE_UMASK" -lt 022 ]; then
            U_30_1=1
        else
            U_30_1=0
        fi
    fi
else
    U_30_1=1 # 파일이 없으면 취약
fi

# --- [U_30_2] /etc/login.defs 파일 점검 ---
# /etc/login.defs 내 UMASK 설정 확인

LOGIN_DEFS="/etc/login.defs"
LOGIN_UMASK=""

if [ -f "$LOGIN_DEFS" ]; then
    # 주석 제외, UMASK 값 추출
    LOGIN_UMASK=$(grep -i "^[[:space:]]*UMASK" "$LOGIN_DEFS" | grep -v "^#" | tail -n 1 | awk '{print $2}')

    if [ -z "$LOGIN_UMASK" ]; then
        # 설정이 없으면 취약
        U_30_2=1
    else
        # 022보다 작으면 취약
        if [ "$LOGIN_UMASK" -lt 022 ]; then
            U_30_2=1
        else
            U_30_2=0
        fi
    fi
else
    U_30_2=1 # 파일이 없으면 취약
fi

# --- 전체 결과 집계 ---
if [ $U_30_1 -eq 1 ] || [ $U_30_2 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-30",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_30_1": $U_30_1,
      "U_30_2": $U_30_2
    },
    "timestamp": "$DATE"
  }
}
EOF