#!/bin/bash

# [U-60] SNMP Community String의 복잡성 설정 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-60"
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
U_60_1=0; IS_VUL=0

# 복잡성 체크 함수
check_snmp_complexity() {
    local str=$1
    if [[ "$str" == "public" || "$str" == "private" ]]; then return 1; fi
    if [[ "$str" =~ [^a-zA-Z0-9] ]]; then
        if [ ${#str} -lt 8 ]; then return 1; fi
    else
        if [ ${#str} -lt 10 ]; then return 1; fi
    fi
    return 0
}

# --- 점검 로직 수행 ---

SNMPD_CONF="/etc/snmp/snmpd.conf"

if [[ -f "$SNMPD_CONF" ]]; then
    # Community String 추출 (Debian 계열 기준 rocommunity/rwcommunity)
    COMMS_LINES=$(run_cmd "[U_60_1] Community String 추출" "grep -E '^rocommunity|^rwcommunity' \"$SNMPD_CONF\" | grep -v '^#' || echo 'none'")
    
    if [[ "$COMMS_LINES" != "none" ]]; then
        # 줄 단위로 읽어서 체크
        WEAK_FOUND=0
        WEAK_STR=""
        
        while read -r line; do
            # 2번째 필드가 community string
            COMM_STR=$(echo "$line" | awk '{print $2}')
            if ! check_snmp_complexity "$COMM_STR"; then
                WEAK_FOUND=1
                WEAK_STR="$COMM_STR"
                break
            fi
        done <<< "$COMMS_LINES"
        
        if [[ "$WEAK_FOUND" -eq 1 ]]; then
            U_60_1=1
            log_basis "[U_60_1] 취약한 Community String 발견: $WEAK_STR" "취약"
        else
            log_basis "[U_60_1] Community String 복잡성 만족" "양호"
        fi
    else
        U_60_1=0
        log_basis "[U_60_1] Community String 설정(rocommunity/rwcommunity)이 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_60_1] SNMP 설정 파일 확인" "ls /etc/snmp/snmpd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_60_1] SNMP 설정 파일 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_60_1 -eq 1 ]]; then
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
      "U_60_1": $U_60_1
    },
    "timestamp": "$DATE"
  }
}
EOF
