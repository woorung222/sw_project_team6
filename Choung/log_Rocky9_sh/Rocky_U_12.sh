#!/bin/bash

# [U-12] 세션 종료 시간 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 
#   U_12_1 : [bash] TMOUT 설정이 600(초) 이하인 경우 양호
#   U_12_2 : [csh] autologout 설정이 10(분) 이하인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-12"
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
U_12_1=0
U_12_2=0
IS_VUL=0

# --- [U_12_1] bash, ksh, sh 점검 (TMOUT) ---
# TMOUT 값 추출 명령
CMD_TMOUT="grep -rh 'TMOUT=' /etc/profile /etc/profile.d/ 2>/dev/null | grep -v '^#' | awk -F= '{print \$2}' | tr -d ' ' | grep -o '[0-9]*' | sort -n | head -1"
TMOUT_VAL=$(run_cmd "[U_12_1] TMOUT 설정값 확인" "$CMD_TMOUT")

if [ -z "$TMOUT_VAL" ]; then
    # 설정이 없으면 취약
    U_12_1=1
    log_basis "[U_12_1] TMOUT(세션타임아웃) 설정이 없음" "취약"
else
    # 값이 존재하면 600초 이하인지 확인
    if [ "$TMOUT_VAL" -le 600 ]; then
        U_12_1=0
        log_basis "[U_12_1] TMOUT 설정($TMOUT_VAL)이 600초 이하임" "양호"
    else
        U_12_1=1
        log_basis "[U_12_1] TMOUT 설정($TMOUT_VAL)이 600초를 초과함" "취약"
    fi
fi


# --- [U_12_2] csh 점검 (autologout) ---
CSH_FILES="/etc/csh.login /etc/csh.cshrc"
AUTO_VAL=""

# 파일이 존재하는 경우에만 점검 (ls 명령어도 run_cmd 처리 가능하지만 단순 조건문용이라 생략하거나 간단히 처리)
if ls $CSH_FILES 1> /dev/null 2>&1; then
    # autologout 값 추출 명령
    CMD_AUTO="grep -rh 'autologout' $CSH_FILES 2>/dev/null | grep -v '^#' | awk -F= '{print \$2}' | tr -d ' ' | grep -o '[0-9]*' | sort -n | head -1"
    AUTO_VAL=$(run_cmd "[U_12_2] autologout 설정값 확인" "$CMD_AUTO")
fi

if [ -z "$AUTO_VAL" ]; then
    U_12_2=1 # 설정 없음
    log_basis "[U_12_2] csh autologout 설정이 없음" "취약"
else
    # 10분 이하인지 확인
    if [ "$AUTO_VAL" -le 10 ]; then
        U_12_2=0
        log_basis "[U_12_2] csh autologout 설정($AUTO_VAL)이 10분 이하임" "양호"
    else
        U_12_2=1
        log_basis "[U_12_2] csh autologout 설정($AUTO_VAL)이 10분을 초과함" "취약"
    fi
fi

# csh 미설치 시 예외 처리 (선택 사항 로직 유지)
if ! command -v csh &> /dev/null; then
    U_12_2=0
    log_basis "[U_12_2] csh이 설치되어 있지 않아 해당 없음(양호)" "양호"
fi


# --- 전체 결과 집계 ---
if [ $U_12_1 -eq 1 ] || [ $U_12_2 -eq 1 ]; then
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
    "flag_id": "U-12",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_12_1": $U_12_1,
      "U_12_2": $U_12_2
    },
    "timestamp": "$DATE"
  }
}
EOF
