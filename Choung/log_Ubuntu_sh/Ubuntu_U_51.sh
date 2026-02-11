#!/bin/bash

# [U-51] DNS 서비스의 취약한 동적 업데이트 설정 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-51"
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
U_51_1=0; U_51_2=0; IS_VUL=0

# --- 점검 로직 수행 ---

NAMED_CONF="/etc/bind/named.conf.options"
if [[ ! -f "$NAMED_CONF" ]]; then NAMED_CONF="/etc/bind/named.conf"; fi
if [[ ! -f "$NAMED_CONF" ]]; then NAMED_CONF="/etc/named.conf"; fi

if [[ -f "$NAMED_CONF" ]]; then
    ALLOW_UPDATE=$(run_cmd "[U_51_1] allow-update 설정 확인" "grep -r 'allow-update' \"$NAMED_CONF\" | grep -v '^#' || echo 'none'")

    if [[ "$ALLOW_UPDATE" != "none" ]]; then
        if echo "$ALLOW_UPDATE" | grep -q "{.*none;.*}"; then
            U_51_1=0
            log_basis "[U_51_1] allow-update가 none으로 설정됨: $ALLOW_UPDATE" "양호"
        else
            if echo "$ALLOW_UPDATE" | grep -q "any"; then
                U_51_2=1
                log_basis "[U_51_2] allow-update가 any로 설정됨: $ALLOW_UPDATE" "취약"
            else
                U_51_2=0
                log_basis "[U_51_2] allow-update가 특정 IP로 제한됨" "양호"
            fi
        fi
    else
        U_51_1=0
        log_basis "[U_51_1] allow-update 설정 미존재 (기본값)" "양호"
    fi
else
    # [증빙 로그 추가]
    TMP=$(run_cmd "[U_51_1] DNS 설정 파일 확인" "ls /etc/bind/named.conf* /etc/named.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_51_1] DNS 설정 파일 미존재" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_51_1 -eq 1 || $U_51_2 -eq 1 ]]; then
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
      "U_51_1": $U_51_1,
      "U_51_2": $U_51_2
    },
    "timestamp": "$DATE"
  }
}
EOF