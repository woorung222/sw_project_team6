#!/bin/bash

# [U-05] root 이외의 UID가 ‘0’ 금지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : root 계정 외에 UID가 0인 계정이 존재하지 않으면 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-05"
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
U_05_1=0
IS_VUL=0

# --- 점검 시작 ---

# 1. UID 0인 비-root 계정 검색
PASSWD_FILE="/etc/passwd"

if [ -f "$PASSWD_FILE" ]; then
    # awk 로직: 구분자(:) 기준 3번째 필드(UID)가 0이면서, 1번째 필드(계정명)가 root가 아닌 경우 출력
    # run_cmd 인자 전달을 위해 내부 따옴표와 $ 기호를 이스케이프 처리
    CMD="awk -F: '\$3 == 0 && \$1 != \"root\" {print \$1}' $PASSWD_FILE"
    
    UID_ZERO_ACCOUNTS=$(run_cmd "[U_05_1] root 외 UID 0 계정 검색" "$CMD")

    if [ -z "$UID_ZERO_ACCOUNTS" ]; then
        # root 외에 UID 0인 계정이 없음 (양호)
        U_05_1=0
        log_basis "[U_05_1] root 계정 외에 UID가 0인 계정이 존재하지 않음" "양호"
    else
        # root 외에 UID 0인 계정이 존재함 (취약)
        U_05_1=1
        # 결과가 여러 줄일 경우 한 줄로 변환 (로그 가독성)
        ACCOUNTS_LIST=$(echo "$UID_ZERO_ACCOUNTS" | tr '\n' ',' | sed 's/,$//')
        log_basis "[U_05_1] root 외 UID 0 계정 발견: $ACCOUNTS_LIST" "취약"
    fi
else
    # /etc/passwd 파일이 없는 심각한 경우
    U_05_1=1
    log_step "[U_05_1] 패스워드 파일 점검" "[ -f $PASSWD_FILE ]" "파일 없음"
    log_basis "[U_05_1] /etc/passwd 파일이 존재하지 않아 점검 불가" "취약"
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_05_1

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
    "is_auto": 0,
    "category": "account",
    "flag": {
      "U_05_1": $U_05_1
    },
    "timestamp": "$DATE"
  }
}
EOF
