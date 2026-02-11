#!/bin/bash

# [U-67] 로그 파일 소유자 및 권한 설정
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-67"
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
U_67_1=0; IS_VUL=0

# 점검할 주요 로그 파일 목록
LOG_FILES=("/var/log/messages" "/var/log/secure" "/var/log/maillog" "/var/log/cron" "/var/log/boot.log" "/var/log/dmesg" "/var/log/syslog")

# --- 점검 로직 시작 ---

for FILE in "${LOG_FILES[@]}"; do
    if [[ -f "$FILE" ]]; then
        O=$(run_cmd "[U_67_1] $FILE 소유자 확인" "stat -c '%U' '$FILE'")
        P=$(run_cmd "[U_67_1] $FILE 권한 확인" "stat -c '%a' '$FILE'")
        
        if [[ "$O" != "root" ]] || [[ "$P" -gt 644 ]]; then
            U_67_1=1
            log_basis "[U_67_1] 로그 파일($FILE)의 소유자($O) 또는 권한($P)이 부적절함 (기준: root / 644 이하)" "취약"
        fi
    else
        log_basis "[U_67_1] 로그 파일($FILE)이 존재하지 않음 (안 깔려 있음/파일 없음)" "양호"
    fi
done

if [[ $U_67_1 -eq 0 ]]; then
    log_basis "[U_67_1] 모든 주요 로그 파일의 소유자 및 권한 설정이 양호함" "양호"
fi

IS_VUL=$U_67_1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-67",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "log",
    "flag": {
      "U_67_1": $U_67_1
    },
    "timestamp": "$DATE"
  }
}
EOF
