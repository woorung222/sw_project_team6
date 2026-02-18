#!/bin/bash

# [U-02] 패스워드 복잡성 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 비밀번호 관리 정책(복잡성, 사용기간, 기억)이 설정된 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (0: 양호, 1: 취약)
U_02_1=0 
IS_VUL=0
VULN_REASONS=() # 취약 원인을 담을 배열

# --- 점검 시작 ---

# 1. 패스워드 최대/최소 사용 기간 점검 (/etc/login.defs)
LOGIN_DEFS="/etc/login.defs"
PASS_MAX=$(grep "^PASS_MAX_DAYS" $LOGIN_DEFS | awk '{print $2}')
PASS_MIN=$(grep "^PASS_MIN_DAYS" $LOGIN_DEFS | awk '{print $2}')

# PASS_MAX_DAYS가 90 이하인지 확인 (설정 없으면 취약)
if [ -z "$PASS_MAX" ] || [ "$PASS_MAX" -gt 90 ]; then
    U_02_1=1
    VULN_REASONS+=("PASS_MAX_DAYS($PASS_MAX) 미설정 또는 90일 초과")
fi

# PASS_MIN_DAYS가 1 이상인지 확인 (설정 없으면 취약)
if [ -z "$PASS_MIN" ] || [ "$PASS_MIN" -lt 1 ]; then
    U_02_1=1
    VULN_REASONS+=("PASS_MIN_DAYS($PASS_MIN) 미설정 또는 1일 미만")
fi


# 2. 패스워드 복잡성 점검 (/etc/security/pwquality.conf)
# Rocky 9에서는 pwquality.conf를 주로 사용
PWQUALITY_CONF="/etc/security/pwquality.conf"
MINLEN=$(grep "^minlen" $PWQUALITY_CONF | awk -F= '{print $2}' | tr -d ' ')
CREDITS=$(grep -E "^[udlo]credit" $PWQUALITY_CONF | awk -F= '{print $2}' | tr -d ' ')

# 최소 길이 8자 이상 확인
if [ -z "$MINLEN" ] || [ "$MINLEN" -lt 8 ]; then
    U_02_1=1
    VULN_REASONS+=("최소 길이(minlen) 8자 미만 또는 미설정")
fi

# 문자 클래스 설정 확인 (하나라도 -1 이하로 설정되어 있거나 복잡성 설정이 있는지)
# 간단하게 확인하기 위해 credit 설정이 하나라도 존재하는지 확인
if [ -z "$CREDITS" ]; then
    # 혹시 system-auth에 설정되어 있을 수도 있으므로 추가 확인 가능하지만,
    # 가이드 기준으로는 설정 파일 점검이 우선.
    U_02_1=1
    VULN_REASONS+=("복잡성(credit) 설정 미흡")
fi


# 3. 패스워드 기억 점검 (/etc/security/pwhistory.conf 또는 system-auth)
# Rocky 9 / RHEL 8 이상에서는 pwhistory.conf 사용 권장
PWHISTORY_CONF="/etc/security/pwhistory.conf"
REMEMBER_VAL=""

if [ -f "$PWHISTORY_CONF" ]; then
    REMEMBER_VAL=$(grep "^remember" $PWHISTORY_CONF | awk -F= '{print $2}' | tr -d ' ')
fi

# pwhistory.conf에 없으면 system-auth에서 pam_pwhistory.so 확인
if [ -z "$REMEMBER_VAL" ]; then
    REMEMBER_VAL=$(grep "pam_pwhistory.so" /etc/pam.d/system-auth | grep -o "remember=[0-9]*" | awk -F= '{print $2}')
fi

# remember 값이 4 이상인지 확인
if [ -z "$REMEMBER_VAL" ] || [ "$REMEMBER_VAL" -lt 4 ]; then
    U_02_1=1
    VULN_REASONS+=("최근 비밀번호 기억(remember) 4회 미만 또는 미설정")
fi


# --- 전체 결과 집계 ---
if [ $U_02_1 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- JSON 출력 ---
# 취약 원인이 있으면 로그로 남기거나 디버깅용으로 쓸 수 있지만, 
# 요청하신 JSON 포맷에는 포함되지 않으므로 값만 출력합니다.
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-02",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_02_1": $U_02_1
    },
    "timestamp": "$DATE"
  }
}
EOF