#!/bin/bash

# [U-03] 계정 잠금 임계값 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 
#   U_03_1 : pam_tally.so 임계값 10회 이하 (Rocky 9 미사용 -> 양호)
#   U_03_2 : pam_tally2.so 임계값 10회 이하 (Rocky 9 미사용 -> 양호)
#   U_03_3 : faillock(authselect) 임계값 10회 이하 (주요 점검 대상)

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (0: 양호, 1: 취약)
U_03_1=0 
U_03_2=0 
U_03_3=0 
IS_VUL=0

PAM_SYSTEM="/etc/pam.d/system-auth"
PAM_PASSWORD="/etc/pam.d/password-auth"
FAILLOCK_CONF="/etc/security/faillock.conf"

# --- [U_03_1] pam_tally.so 점검 ---
# Rocky 9에서는 기본적으로 사용하지 않으므로 설정 파일에 모듈이 있는지만 확인
TALLY_CHECK=$(grep -E "^auth.*required.*pam_tally.so" $PAM_SYSTEM $PAM_PASSWORD 2>/dev/null)

if [ ! -z "$TALLY_CHECK" ]; then
    # 설정이 존재하면 deny 값 확인
    DENY_VAL=$(echo "$TALLY_CHECK" | grep -o "deny=[0-9]*" | cut -d= -f2)
    if [ -z "$DENY_VAL" ] || [ "$DENY_VAL" -gt 10 ]; then
        U_03_1=1
    else
        U_03_1=0
    fi
else
    # 모듈을 사용하지 않으면 양호
    U_03_1=0
fi

# --- [U_03_2] pam_tally2.so 점검 ---
TALLY2_CHECK=$(grep -E "^auth.*required.*pam_tally2.so" $PAM_SYSTEM $PAM_PASSWORD 2>/dev/null)

if [ ! -z "$TALLY2_CHECK" ]; then
    DENY_VAL=$(echo "$TALLY2_CHECK" | grep -o "deny=[0-9]*" | cut -d= -f2)
    if [ -z "$DENY_VAL" ] || [ "$DENY_VAL" -gt 10 ]; then
        U_03_2=1
    else
        U_03_2=0
    fi
else
    # 모듈을 사용하지 않으면 양호
    U_03_2=0
fi

# --- [U_03_3] faillock (authselect) 점검 ---
# Rocky 9의 표준 잠금 모듈
# 1. faillock.conf 파일 점검
DENY_VAL=""
if [ -f "$FAILLOCK_CONF" ]; then
    DENY_VAL=$(grep "^deny" "$FAILLOCK_CONF" | awk -F= '{print $2}' | tr -d ' ')
fi

# 2. 만약 conf 파일에 없으면 pam 파일의 파라미터 확인
if [ -z "$DENY_VAL" ]; then
    DENY_VAL=$(grep "pam_faillock.so" "$PAM_SYSTEM" | grep -o "deny=[0-9]*" | head -1 | cut -d= -f2)
fi

# 3. 판단 (설정이 없거나, 0이거나, 10 초과면 취약)
if [ -z "$DENY_VAL" ]; then
    U_03_3=1 # 설정 없음
elif [ "$DENY_VAL" -eq 0 ] || [ "$DENY_VAL" -gt 10 ]; then
    U_03_3=1 # 비활성 또는 기준 초과
else
    U_03_3=0 # 양호
fi

# --- 전체 결과 집계 ---
# 하나라도 취약하면 전체 취약
if [ $U_03_1 -eq 1 ] || [ $U_03_2 -eq 1 ] || [ $U_03_3 -eq 1 ]; then
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
    "flag_id": "U-03",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_03_1": $U_03_1,
      "U_03_2": $U_03_2,
      "U_03_3": $U_03_3
    },
    "timestamp": "$DATE"
  }
}
EOF