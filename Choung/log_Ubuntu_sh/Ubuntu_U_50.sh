#!/bin/bash

# [U-50] Secondary Name Server로만 Zone 정보 전송 제한 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-50"
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
U_50_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

NAMED_CONF=""
if [[ -f "/etc/bind/named.conf.options" ]]; then NAMED_CONF="/etc/bind/named.conf.options";
elif [[ -f "/etc/named.conf" ]]; then NAMED_CONF="/etc/named.conf";
elif [[ -f "/etc/bind/named.conf" ]]; then NAMED_CONF="/etc/bind/named.conf"; fi

if [[ -n "$NAMED_CONF" ]]; then
    ALLOW_TRANSFER=$(run_cmd "[U_50_1] allow-transfer 설정 확인" "grep 'allow-transfer' \"$NAMED_CONF\" | grep -v '^#' || echo 'none'")
    
    if [[ "$ALLOW_TRANSFER" != "none" ]]; then
        if echo "$ALLOW_TRANSFER" | grep -q "any"; then
            U_50_1=1
            log_basis "[U_50_1] Zone Transfer 설정에 'any' 포함: $ALLOW_TRANSFER" "취약"
        else
            log_basis "[U_50_1] Zone Transfer 설정 제한됨: $ALLOW_TRANSFER" "양호"
        fi
    else
        U_50_1=1
        log_basis "[U_50_1] allow-transfer 설정 미존재 (기본 취약)" "취약"
    fi
else
    # [증빙 로그 추가] 파일 없음 확인
    TMP=$(run_cmd "[U_50_1] DNS 설정 파일 확인" "ls /etc/bind/named.conf* /etc/named.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_50_1] DNS 설정 파일이 존재하지 않음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_50_1 -eq 1 ]]; then
    IS_VUL=1
fi

# JSON 출력
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
    "category": "service",
    "flag": {
      "U_50_1": $U_50_1
    },
    "timestamp": "$DATE"
  }
}
EOF