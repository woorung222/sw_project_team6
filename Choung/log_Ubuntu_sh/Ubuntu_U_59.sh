#!/bin/bash

# [U-59] 안전한 SNMP 버전(v3 이상) 사용 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-59"
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
U_59_1=0; IS_VUL=0

# --- 점검 로직 수행 ---

# [U_59_1] SNMP 서비스 및 버전 설정 확인
# 서비스 구동 여부 확인
SNMP_ACTIVE=$(run_cmd "[U_59_1] snmpd 활성 상태" "systemctl is-active snmpd 2>/dev/null || echo 'inactive'")

if [[ "$SNMP_ACTIVE" == "active" ]]; then
    SNMPD_CONF="/etc/snmp/snmpd.conf"
    
    if [[ -f "$SNMPD_CONF" ]]; then
        # v3 설정 확인
        V3_CHECK=$(run_cmd "[U_59_1] v3 설정 확인" "grep -E 'createUser|rouser|authPriv' \"$SNMPD_CONF\" | grep -v '^#' || echo 'none'")
        
        # v1, v2c 설정 확인
        V1_V2_CHECK=$(run_cmd "[U_59_1] v1/v2 설정 확인" "grep -E 'rocommunity|rwcommunity|com2sec' \"$SNMPD_CONF\" | grep -v '^#' || echo 'none'")

        if [[ "$V3_CHECK" != "none" ]] && [[ "$V1_V2_CHECK" == "none" ]]; then
            U_59_1=0
            log_basis "[U_59_1] SNMP v3 설정 존재 및 v1/v2 설정 없음" "양호"
        else
            U_59_1=1
            log_basis "[U_59_1] v3 설정 미흡($V3_CHECK) 또는 v1/v2 설정 존재($V1_V2_CHECK)" "취약"
        fi
    else
        # 서비스는 도는데 설정 파일이 없는 경우
        U_59_1=1
        TMP=$(run_cmd "[U_59_1] 설정 파일 확인" "ls /etc/snmp/snmpd.conf 2>/dev/null || echo '파일 미존재'")
        log_basis "[U_59_1] snmpd 활성 상태이나 설정 파일(/etc/snmp/snmpd.conf)을 찾을 수 없음" "취약"
    fi
else
    U_59_1=0
    log_basis "[U_59_1] snmpd 서비스 비활성화" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_59_1 -eq 1 ]]; then
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
      "U_59_1": $U_59_1
    },
    "timestamp": "$DATE"
  }
}
EOF
