#!/bin/bash

# [U-12] /etc/services 파일 소유자 및 권한 설정
# 대상 운영체제 : Ubuntu 24.04

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

# 초기화
U_12_1=1; IS_VUL=0

# --- 점검 로직 시작 ---

SERVICES_FILE="/etc/services"

# 1. 존재 여부 확인 (진단 내용 cmd 기록용)
CHECK_FILE=$(run_cmd "[U_12_1] $SERVICES_FILE 존재 확인" "ls $SERVICES_FILE 2>/dev/null || echo '파일 없음'")

if [[ -f "$SERVICES_FILE" ]]; then
    # 소유자 및 권한 확인
    U=$(run_cmd "[U_12_1] $SERVICES_FILE 소유자 확인" "stat -c '%U' '$SERVICES_FILE'")
    M=$(run_cmd "[U_12_1] $SERVICES_FILE 권한 확인" "stat -c '%a' '$SERVICES_FILE'")

    # 판정 로직: 소유자 root 및 권한 644 이하 (그룹/기타 쓰기 금지)
    # Ubuntu 기준: group/other write 비트(2) 포함 여부 체크
    if [[ "$U" == "root" ]] && [[ "$M" -le 644 ]] && [[ ! "$M" =~ [2367]$ ]] && [[ ! "$M" =~ ^[0-9][2367][0-9]$ ]]; then
        U_12_1=0
        log_basis "[U_12_1] $SERVICES_FILE 설정 양호 (소유자: $U, 권한: $M)" "양호"
    else
        U_12_1=1
        log_basis "[U_12_1] $SERVICES_FILE 설정 미흡 (소유자: $U, 권한: $M)" "취약"
    fi
else
    log_step "[U_12_1] 파일 확인" "ls $SERVICES_FILE" "파일 없음"
    U_12_1=1
fi

IS_VUL=$U_12_1

# --- JSON 출력 (개행 양식 준수) ---
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
      "U_12_1": $U_12_1
    },
    "timestamp": "$DATE"
  }
}
EOF
