#!/bin/bash

# [U-61] SNMP 서비스 사용 시 특정 호스트만 접속 허용 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-61"
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
U_61_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

SNMPD_CONF="/etc/snmp/snmpd.conf"
SNMP_ACTIVE=$(systemctl is-active --quiet snmpd && echo "yes" || echo "no")

if [[ "$SNMP_ACTIVE" == "yes" ]] || [[ -f "$SNMPD_CONF" ]]; then
    
    if [[ -f "$SNMPD_CONF" ]]; then
        # rocommunity/rwcommunity 설정 라인 추출
        COMM_LINES=$(run_cmd "[U_61_1] 접근 제어 설정 확인" "grep -E '^rocommunity|^rwcommunity' \"$SNMPD_CONF\" | grep -v '^#' || echo 'none'")
        
        if [[ "$COMM_LINES" != "none" ]]; then
            VULN_FOUND=0
            VULN_LINE=""
            
            while read -r line; do
                # 3번째 필드가 Source IP (없으면 취약으로 간주될 수 있음)
                ADDR=$(echo "$line" | awk '{print $3}')
                
                # IP가 없거나, default, 0.0.0.0 대역인 경우 취약
                if [[ -z "$ADDR" ]] || [[ "$ADDR" == "default" ]] || [[ "$ADDR" == "0.0.0.0/0" ]] || [[ "$ADDR" == "0.0.0.0" ]]; then
                    VULN_FOUND=1
                    VULN_LINE="$line"
                    break
                fi
            done <<< "$COMM_LINES"
            
            if [[ "$VULN_FOUND" -eq 1 ]]; then
                U_61_1=1
                log_basis "[U_61_1] SNMP 접근 제어 미흡 설정 발견: $VULN_LINE" "취약"
            else
                log_basis "[U_61_1] SNMP 접근 제어 설정 양호" "양호"
            fi
        else
             # 설정이 없으면 서비스 동작 방식에 따라 다르나, 여기선 설정 파일 내 명시적 허용이 없으므로 양호로 처리하거나,
             # 또는 기본적으로 차단된다고 가정.
             U_61_1=0
             log_basis "[U_61_1] SNMP 커뮤니티 설정 라인이 없음" "양호"
        fi
    else
        # 서비스는 도는데 파일이 없음
        U_61_1=1
        TMP=$(run_cmd "[U_61_1] 설정 파일 확인" "ls /etc/snmp/snmpd.conf 2>/dev/null || echo '파일 미존재'")
        log_basis "[U_61_1] snmpd 구동 중이나 설정 파일 미존재" "취약"
    fi
else
    # 서비스 안 돌고 파일도 없음
    U_61_1=0
    TMP=$(run_cmd "[U_61_1] 서비스/파일 확인" "echo 'Service inactive & File missing'")
    log_basis "[U_61_1] SNMP 서비스 미사용" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_61_1 -eq 1 ]]; then
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
      "U_61_1": $U_61_1
    },
    "timestamp": "$DATE"
  }
}
EOF
