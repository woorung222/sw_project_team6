#!/bin/bash

# [U-61] SNMP 서비스 접근 통제
# 대상 운영체제 : Rocky Linux 9

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

# 초기화 (0: 양호, 1: 취약)
U_61_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 패키지 설치 여부 정밀 확인 (net-snmp 데몬)
# 설치 여부 확인 과정을 run_cmd로 기록
SNMP_PKG=$(run_cmd "[61] net-snmp 패키지 설치 확인" "rpm -qa | grep -qE '^net-snmp-[0-9]' && echo '설치됨' || echo '안 깔려 있음'")

if [[ "$SNMP_PKG" == "설치됨" ]]; then
    SNMP_CONF="/etc/snmp/snmpd.conf"
    
    # 2. com2sec 설정 점검 (U_61_1)
    if [[ -f "$SNMP_CONF" ]]; then
        # 취약한 접근 제어(Source) 설정 확인 과정을 run_cmd로 기록
        # Source가 'default' 또는 '0.0.0.0' 인 설정을 검색
        WEAK_CONFIG=$(run_cmd "[U_61_1] com2sec 취약 설정(default/0.0.0.0) 확인" "grep -v '^#' '$SNMP_CONF' 2>/dev/null | grep 'com2sec' | awk '\$3 == \"default\" || \$3 == \"0.0.0.0\"' || echo '없음'")
        
        if [[ "$WEAK_CONFIG" != "없음" ]]; then
            U_61_1=1
            log_basis "[U_61_1] SNMP 접근 제어 설정이 전체 허용(default 또는 0.0.0.0)으로 되어 있어 취약함" "취약"
        else
            log_basis "[U_61_1] SNMP 접근 제어 설정이 적절히 제한되어 양호함" "양호"
        fi
    else
        log_step "[U_61_1] 설정 파일 확인" "ls $SNMP_CONF" "파일 없음"
        log_basis "[U_61_1] SNMP 설정 파일이 존재하지 않아 양호함" "양호"
    fi
else
    # 패키지 미설치 시 로깅
    log_basis "[U_61_1] SNMP 서비스 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_61_1

# 4. JSON 출력 (원본 구조 및 플래그 명칭 절대 유지)
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
    "category": "service_management",
    "flag": {
      "U_61_1": $U_61_1
    },
    "timestamp": "$DATE"
  }
}
EOF
