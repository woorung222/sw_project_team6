#!/bin/bash

# [U-03] 계정 잠금 임계값 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 계정 잠금 임계값이 10회 이하로 설정되어 있으면 양호
#             (Rocky 9은 faillock이 표준이며, pam_tally는 미사용 시 양호)

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-03"
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
U_03_1=0 
U_03_2=0 
U_03_3=0 
IS_VUL=0

PAM_SYSTEM="/etc/pam.d/system-auth"
PAM_PASSWORD="/etc/pam.d/password-auth"
FAILLOCK_CONF="/etc/security/faillock.conf"

# --- 점검 로직 시작 ---

# ---------------------------------------------------------
# 1. [U_03_1] pam_tally.so 점검
# ---------------------------------------------------------
# Rocky 9에서는 기본적으로 사용하지 않으므로 설정 파일에 모듈이 있는지만 확인
TALLY_CHECK=$(run_cmd "[U_03_1] pam_tally.so 설정 확인" "grep -E '^auth.*required.*pam_tally.so' $PAM_SYSTEM $PAM_PASSWORD 2>/dev/null")

if [ -n "$TALLY_CHECK" ]; then
    # 설정이 존재하면 deny 값 확인
    DENY_VAL=$(echo "$TALLY_CHECK" | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
    
    if [ -z "$DENY_VAL" ]; then
        U_03_1=1
        log_basis "[U_03_1] pam_tally.so 모듈이 존재하나 deny 값이 설정되지 않음" "취약"
    elif [ "$DENY_VAL" -gt 10 ]; then
        U_03_1=1
        log_basis "[U_03_1] pam_tally.so 임계값($DENY_VAL)이 10회를 초과함" "취약"
    else
        U_03_1=0
        log_basis "[U_03_1] pam_tally.so 임계값($DENY_VAL)이 10회 이하로 설정됨" "양호"
    fi
else
    # 모듈을 사용하지 않으면 양호 (Rocky 9 기본)
    U_03_1=0
    log_basis "[U_03_1] pam_tally.so 모듈을 사용하지 않음 (Rocky 9 기본)" "양호"
fi

# ---------------------------------------------------------
# 2. [U_03_2] pam_tally2.so 점검
# ---------------------------------------------------------
TALLY2_CHECK=$(run_cmd "[U_03_2] pam_tally2.so 설정 확인" "grep -E '^auth.*required.*pam_tally2.so' $PAM_SYSTEM $PAM_PASSWORD 2>/dev/null")

if [ -n "$TALLY2_CHECK" ]; then
    DENY_VAL=$(echo "$TALLY2_CHECK" | grep -o "deny=[0-9]*" | cut -d= -f2 | head -1)
    
    if [ -z "$DENY_VAL" ]; then
        U_03_2=1
        log_basis "[U_03_2] pam_tally2.so 모듈이 존재하나 deny 값이 설정되지 않음" "취약"
    elif [ "$DENY_VAL" -gt 10 ]; then
        U_03_2=1
        log_basis "[U_03_2] pam_tally2.so 임계값($DENY_VAL)이 10회를 초과함" "취약"
    else
        U_03_2=0
        log_basis "[U_03_2] pam_tally2.so 임계값($DENY_VAL)이 10회 이하로 설정됨" "양호"
    fi
else
    # 모듈을 사용하지 않으면 양호
    U_03_2=0
    log_basis "[U_03_2] pam_tally2.so 모듈을 사용하지 않음 (Rocky 9 기본)" "양호"
fi

# ---------------------------------------------------------
# 3. [U_03_3] faillock (authselect) 점검
# ---------------------------------------------------------
# Rocky 9의 표준 잠금 모듈
DENY_VAL=""

# 3-1. faillock.conf 파일 점검
if [ -f "$FAILLOCK_CONF" ]; then
    DENY_VAL=$(run_cmd "[U_03_3] faillock.conf 내 deny 값 확인" "grep '^deny' $FAILLOCK_CONF | awk -F= '{print \$2}' | tr -d ' '")
fi

# 3-2. 만약 conf 파일에 없으면 pam 파일의 파라미터 확인
if [ -z "$DENY_VAL" ]; then
    DENY_VAL=$(run_cmd "[U_03_3] PAM 파일 내 faillock deny 값 확인" "grep 'pam_faillock.so' $PAM_SYSTEM | grep -o 'deny=[0-9]*' | head -1 | cut -d= -f2")
fi

# 3-3. 판단 (설정이 없거나, 0이거나, 10 초과면 취약)
if [ -z "$DENY_VAL" ]; then
    U_03_3=1 # 설정 없음
    log_basis "[U_03_3] faillock 임계값(deny) 설정이 존재하지 않음" "취약"
elif [ "$DENY_VAL" -eq 0 ]; then
    U_03_3=1 # 비활성
    log_basis "[U_03_3] faillock 임계값이 0(잠금 비활성)으로 설정됨" "취약"
elif [ "$DENY_VAL" -gt 10 ]; then
    U_03_3=1 # 기준 초과
    log_basis "[U_03_3] faillock 임계값($DENY_VAL)이 10회를 초과함" "취약"
else
    U_03_3=0 # 양호
    log_basis "[U_03_3] faillock 임계값($DENY_VAL)이 10회 이하로 적절히 설정됨" "양호"
fi

# ---------------------------------------------------------
# 4. 전체 결과 집계
# ---------------------------------------------------------
# 하나라도 취약하면 전체 취약
if [ $U_03_1 -eq 1 ] || [ $U_03_2 -eq 1 ] || [ $U_03_3 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# ---------------------------------------------------------
# 5. JSON 출력 (stdout)
# ---------------------------------------------------------
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
      "U_03_1": $U_03_1,
      "U_03_2": $U_03_2,
      "U_03_3": $U_03_3
    },
    "timestamp": "$DATE"
  }
}
EOF
