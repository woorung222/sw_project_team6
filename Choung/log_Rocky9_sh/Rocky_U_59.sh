#!/bin/bash

# [U-59] 안전한 SNMP 버전 사용
# 대상 운영체제 : Rocky Linux 9

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

# 초기화 (0: 양호, 1: 취약)
U_59_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 패키지 설치 여부 확인
# net-snmp 패키지 설치 확인 과정을 run_cmd로 기록
SNMP_PKG=$(run_cmd "[59] net-snmp 패키지 설치 확인" "rpm -qa | grep -q 'net-snmp' && echo '설치됨' || echo '안 깔려 있음'")

if [[ "$SNMP_PKG" == "설치됨" ]]; then
    SNMP_CONF="/etc/snmp/snmpd.conf"
    
    # 2. 설정 파일 점검 (U_59_1)
    if [[ -f "$SNMP_CONF" ]]; then
        # v1/v2c 활성화 지시어 확인 (주석 제외)
        # rocommunity, rwcommunity, com2sec 설정 존재 여부 확인 과정을 run_cmd로 기록
        WEAK_VERS=$(run_cmd "[U_59_1] SNMP v1/v2c 취약 설정(rocommunity, rwcommunity, com2sec) 확인" "grep -v '^#' '$SNMP_CONF' 2>/dev/null | grep -E 'rocommunity|rwcommunity|com2sec' || echo '없음'")
        
        if [[ "$WEAK_VERS" != "없음" ]]; then
            U_59_1=1
            log_basis "[U_59_1] SNMP v1/v2c 사용 설정이 발견되어 취약함" "취약"
        else
            log_basis "[U_59_1] SNMP v1/v2c 사용 설정이 발견되지 않아 양호함" "양호"
        fi
    else
        log_step "[U_59_1] 설정 파일 확인" "ls $SNMP_CONF" "파일 없음"
        log_basis "[U_59_1] SNMP 설정 파일이 존재하지 않아 양호함" "양호"
    fi
else
    # 패키지 미설치 시 로깅
    log_basis "[U_59_1] SNMP 서비스가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_59_1

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
    "category": "service",
    "flag": {
      "U_59_1": $U_59_1
    },
    "timestamp": "$DATE"
  }
}
EOF
