#!/bin/bash

# [U-04] 패스워드 파일 보호 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 쉐도우 비밀번호를 사용(shadow 파일 존재)하고, /etc/passwd의 패스워드 필드가 'x'인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-04"
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
U_04_1=0 
IS_VUL=0

# --- 점검 시작 ---

# 1. /etc/shadow 파일 존재 여부 확인
SHADOW_FILE="/etc/shadow"

if [ ! -f "$SHADOW_FILE" ]; then
    # 쉐도우 파일이 없으면 무조건 취약
    U_04_1=1
    log_step "[U_04_1] shadow 파일 존재 여부" "[ -f $SHADOW_FILE ]" "파일 없음"
    log_basis "[U_04_1] 쉐도우 파일($SHADOW_FILE)이 존재하지 않음" "취약"
else
    # 2. /etc/passwd 파일 내 두 번째 필드가 'x'가 아닌 계정이 있는지 확인
    # run_cmd를 사용하여 결과값(계정 목록)을 변수에 저장함과 동시에 로그 기록
    # awk로 구분자(:) 기준 2번째 필드가 "x"가 아닌 줄의 1번째 필드(계정명)를 찾음
    CMD="awk -F: '\$2 != \"x\" {print \$1}' /etc/passwd"
    NON_SHADOW_ACCOUNTS=$(run_cmd "[U_04_1] 쉐도우 패스워드 미사용 계정 확인" "$CMD")

    if [ -z "$NON_SHADOW_ACCOUNTS" ]; then
        # 'x'가 아닌 계정이 하나도 없으면 양호
        U_04_1=0
        log_basis "[U_04_1] 쉐도우 파일이 존재하고, 모든 계정이 암호화된 패스워드(x)를 사용 중임" "양호"
    else
        # 'x' 표시가 안 된 계정이 발견되면 취약
        U_04_1=1
        # 계정 목록이 길 수 있으므로 로그에는 한 줄로 정리
        ACCOUNTS_ONE_LINE=$(echo "$NON_SHADOW_ACCOUNTS" | tr '\n' ',' | sed 's/,$//')
        log_basis "[U_04_1] 쉐도우 패스워드를 사용하지 않는 계정 발견: $ACCOUNTS_ONE_LINE" "취약"
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
    "flag_id": "$FLAG_ID",
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
