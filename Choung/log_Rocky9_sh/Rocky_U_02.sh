#!/bin/bash

# [U-02] 패스워드 복잡성 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 비밀번호 관리 정책(복잡성, 사용기간, 기억)이 설정된 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-02"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

# 2. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_02_1=0
IS_VUL=0
VULN_REASONS=() # 취약 원인을 담을 배열

# --- 점검 시작 ---

# ---------------------------------------------------------
# 1. 패스워드 최대/최소 사용 기간 점검 (/etc/login.defs)
# ---------------------------------------------------------
LOGIN_DEFS="/etc/login.defs"
if [ -f "$LOGIN_DEFS" ]; then
    # PASS_MAX_DAYS 확인
    PASS_MAX=$(run_cmd "[U_02_1] PASS_MAX_DAYS 값 확인" "grep '^PASS_MAX_DAYS' $LOGIN_DEFS | awk '{print \$2}'")
    
    # PASS_MIN_DAYS 확인
    PASS_MIN=$(run_cmd "[U_02_1] PASS_MIN_DAYS 값 확인" "grep '^PASS_MIN_DAYS' $LOGIN_DEFS | awk '{print \$2}'")

    # PASS_MAX_DAYS가 90 이하인지 확인 (설정 없으면 취약)
    if [ -z "$PASS_MAX" ] || [ "$PASS_MAX" -gt 90 ]; then
        U_02_1=1
        VULN_REASONS+=("PASS_MAX_DAYS(${PASS_MAX:-미설정}) 90일 초과")
    fi

    # PASS_MIN_DAYS가 1 이상인지 확인 (설정 없으면 취약)
    if [ -z "$PASS_MIN" ] || [ "$PASS_MIN" -lt 1 ]; then
        U_02_1=1
        VULN_REASONS+=("PASS_MIN_DAYS(${PASS_MIN:-미설정}) 1일 미만")
    fi
else
    U_02_1=1
    VULN_REASONS+=("login.defs 파일 미존재")
    log_step "[U_02_1] login.defs 파일 점검" "[ -f $LOGIN_DEFS ]" "파일 없음"
fi

# ---------------------------------------------------------
# 2. 패스워드 복잡성 점검 (/etc/security/pwquality.conf)
# ---------------------------------------------------------
# Rocky 9에서는 pwquality.conf를 주로 사용
PWQUALITY_CONF="/etc/security/pwquality.conf"

if [ -f "$PWQUALITY_CONF" ]; then
    # 최소 길이(minlen) 확인
    MINLEN=$(run_cmd "[U_02_1] 최소 길이(minlen) 확인" "grep '^minlen' $PWQUALITY_CONF | awk -F= '{print \$2}' | tr -d ' '")
    
    # 문자 클래스 설정(credit) 확인
    CREDITS=$(run_cmd "[U_02_1] 복잡성 설정(credit) 확인" "grep -E '^[udlo]credit' $PWQUALITY_CONF | awk -F= '{print \$2}' | tr -d ' '")

    # 최소 길이 8자 이상 확인
    if [ -z "$MINLEN" ] || [ "$MINLEN" -lt 8 ]; then
        U_02_1=1
        VULN_REASONS+=("최소 길이(minlen:${MINLEN:-미설정}) 8자 미만")
    fi

    # 문자 클래스 설정 확인 (간단하게 credit 설정 존재 여부 확인)
    if [ -z "$CREDITS" ]; then
        # 혹시 system-auth에 설정되어 있을 수도 있으므로 추가 확인 가능하지만,
        # 가이드 기준으로는 설정 파일 점검이 우선.
        U_02_1=1
        VULN_REASONS+=("복잡성(credit) 설정 미흡")
    fi
else
    U_02_1=1
    VULN_REASONS+=("pwquality.conf 파일 미존재")
    log_step "[U_02_1] pwquality.conf 파일 점검" "[ -f $PWQUALITY_CONF ]" "파일 없음"
fi

# ---------------------------------------------------------
# 3. 패스워드 기억 점검 (/etc/security/pwhistory.conf 등)
# ---------------------------------------------------------
PWHISTORY_CONF="/etc/security/pwhistory.conf"
REMEMBER_VAL=""

if [ -f "$PWHISTORY_CONF" ]; then
    REMEMBER_VAL=$(run_cmd "[U_02_1] pwhistory.conf 내 remember 값 확인" "grep '^remember' $PWHISTORY_CONF | awk -F= '{print \$2}' | tr -d ' '")
fi

# pwhistory.conf에 없으면 system-auth에서 pam_pwhistory.so 확인
if [ -z "$REMEMBER_VAL" ]; then
    REMEMBER_VAL=$(run_cmd "[U_02_1] system-auth 내 pam_pwhistory 확인" "grep 'pam_pwhistory.so' /etc/pam.d/system-auth | grep -o 'remember=[0-9]*' | awk -F= '{print \$2}'")
fi

# remember 값이 4 이상인지 확인
if [ -z "$REMEMBER_VAL" ] || [ "$REMEMBER_VAL" -lt 4 ]; then
    U_02_1=1
    VULN_REASONS+=("최근 비밀번호 기억(${REMEMBER_VAL:-미설정}) 4회 미만")
fi


# --- 전체 결과 집계 ---
if [ $U_02_1 -eq 1 ]; then
    IS_VUL=1
    # 배열에 담긴 취약 원인들을 쉼표로 연결하여 출력
    IFS=,
    log_basis "[U_02_1] 패스워드 정책 미흡: ${VULN_REASONS[*]}" "취약"
    unset IFS
else
    IS_VUL=0
    log_basis "[U_02_1] 패스워드 사용 기간, 복잡성, 기억 설정이 모두 양호함" "양호"
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
    "flag_id": "$FLAG_ID",
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
