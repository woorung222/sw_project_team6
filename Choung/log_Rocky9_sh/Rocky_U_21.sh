#!/bin/bash

# [U-21] /etc/(r)syslog.conf 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자가 root(또는 bin, sys)이고, 권한이 644 이하인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-21"
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
U_21_1=0 # syslog.conf
U_21_2=0 # rsyslog.conf
IS_VUL=0

# --- 함수 정의: 파일 권한 및 소유자 점검 ---
check_file_perm() {
    local FILE=$1
    local FLAG_TAG=$2 # U_21_1 또는 U_21_2
    
    if [ -f "$FILE" ]; then
        # 타이틀 양식 적용: [NN_N]
        local OWNER=$(run_cmd "[$FLAG_TAG] $FILE 소유자 확인" "stat -c '%U' $FILE")
        local PERM=$(run_cmd "[$FLAG_TAG] $FILE 권한 확인" "stat -c '%a' $FILE")
        
        if [[ "$OWNER" == "root" || "$OWNER" == "bin" || "$OWNER" == "sys" ]]; then
            if [ "$PERM" -le 644 ]; then
                log_basis "[$FLAG_TAG] $FILE 소유자($OWNER) 및 권한($PERM) 양호" "양호"
                echo 0
            else
                log_basis "[$FLAG_TAG] $FILE 권한($PERM)이 644를 초과함" "취약"
                echo 1
            fi
        else
            log_basis "[$FLAG_TAG] $FILE 소유자($OWNER)가 부적절함" "취약"
            echo 1
        fi
    else
        log_step "[$FLAG_TAG] 파일 존재 확인" "[ -f $FILE ]" "파일 없음"
        log_basis "[$FLAG_TAG] $FILE 파일이 존재하지 않음 (양호)" "양호"
        echo 0
    fi
}

# --- 점검 실행 ---
U_21_1=$(check_file_perm "/etc/syslog.conf" "U_21_1")
U_21_2=$(check_file_perm "/etc/rsyslog.conf" "U_21_2")

# --- 전체 결과 집계 ---
if [ $U_21_1 -eq 1 ] || [ $U_21_2 -eq 1 ]; then
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
    "flag_id": "U-21",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_21_1": $U_21_1,
      "U_21_2": $U_21_2
    },
    "timestamp": "$DATE"
  }
}
EOF