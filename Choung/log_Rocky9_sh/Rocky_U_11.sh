#!/bin/bash

# [U-11] 사용자 Shell 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 로그인이 필요하지 않은 계정에 /bin/false 또는 /sbin/nologin 쉘이 부여된 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-11"
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
U_11_1=0 
IS_VUL=0
VULN_ACCOUNTS=""

# --- 점검 시작 ---

# 점검할 시스템 계정 목록
CHECK_LIST="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"

for acc in $CHECK_LIST; do
    # 1. /etc/passwd에 해당 계정이 있는지 확인
    # grep 결과를 run_cmd로 확인하면 로그가 너무 많아질 수 있으나, 
    # 원본 로직 유지를 위해 필요한 부분만 run_cmd 적용 (여기서는 단순 grep이라 생략 가능하지만 명시적 확인 위해 적용)
    # 반복 횟수가 많지 않으므로 적용
    ACC_INFO=$(run_cmd "[U_11_1] 계정($acc) 존재 확인" "grep '^$acc:' /etc/passwd")
    
    if [ -n "$ACC_INFO" ]; then
        # 2. 쉘(7번째 필드) 확인
        SHELL=$(echo "$ACC_INFO" | awk -F: '{print $7}')
        
        # 3. 쉘이 /bin/false 또는 /sbin/nologin 인지 확인
        if [[ "$SHELL" != "/bin/false" && "$SHELL" != "/sbin/nologin" && "$SHELL" != "/usr/sbin/nologin" ]]; then
            # 로그인 가능한 쉘을 가진 경우 취약
            U_11_1=1
            VULN_ACCOUNTS="$VULN_ACCOUNTS $acc($SHELL)"
        fi
    fi
done

# --- 최종 결과 집계 ---
IS_VUL=$U_11_1

if [ $U_11_1 -eq 1 ]; then
    log_basis "[U_11_1] 로그인이 필요 없는 계정에 쉘이 부여됨: $VULN_ACCOUNTS" "취약"
else
    log_basis "[U_11_1] 주요 시스템 계정의 쉘 설정이 양호함" "양호"
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
    "flag_id": "U-11",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_11_1": $U_11_1
    },
    "timestamp": "$DATE"
  }
}
EOF
