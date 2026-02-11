#!/bin/bash

# [U-07] /etc/passwd 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-07"
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

# 초기화
U_07_1=1; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. /etc/passwd 점검 (U_07_1)
PASSWD_FILE="/etc/passwd"
if [[ -f "$PASSWD_FILE" ]]; then
    P_USER=$(run_cmd "[U_07_1] $PASSWD_FILE 소유자 확인" "stat -c '%U' '$PASSWD_FILE'")
    P_MODE=$(run_cmd "[U_07_1] $PASSWD_FILE 권한 확인" "stat -c '%a' '$PASSWD_FILE'")

    # 소유자 root, 권한 644 이하
    if [[ "$P_USER" == "root" ]] && [[ "$P_MODE" -le 644 ]] && [[ ! "$P_MODE" =~ [2367]$ ]]; then
        U_07_1=0
        log_basis "[U_07_1] $PASSWD_FILE 설정 양호 (소유자: $P_USER, 권한: $P_MODE)" "양호"
    else
        U_07_1=1
        log_basis "[U_07_1] $PASSWD_FILE 설정 미흡 (소유자: $P_USER, 권한: $P_MODE)" "취약"
    fi
else
    log_step "[U_07_1] 파일 확인" "ls $PASSWD_FILE" "파일 없음"
    U_07_1=1
fi

IS_VUL=$U_07_1

# --- JSON 출력 (요청하신 개행 양식 절대 준수) ---
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
    "category": "file",
    "flag": {
      "U_07_1": $U_07_1
    },
    "timestamp": "$DATE"
  }
}
EOF
