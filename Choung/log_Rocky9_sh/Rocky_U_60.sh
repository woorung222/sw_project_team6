#!/bin/bash

# [U-60] SNMP Community String 복잡성 설정
# 대상 운영체제 : Rocky Linux 9

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

# 초기화 (0: 양호, 1: 취약)
U_60_1=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 패키지 설치 여부 확인
# net-snmp 패키지 설치 확인 과정을 run_cmd로 기록
SNMP_PKG=$(run_cmd "[60] net-snmp 패키지 설치 확인" "rpm -qa | grep -q 'net-snmp' && echo '설치됨' || echo '안 깔려 있음'")

if [[ "$SNMP_PKG" == "설치됨" ]]; then
    SNMP_CONF="/etc/snmp/snmpd.conf"
    
    if [[ -f "$SNMP_CONF" ]]; then
        # 커뮤니티 스트링 추출 및 복잡성 검사 과정을 run_cmd로 기록
        # com2sec, rocommunity, rwcommunity 설정에서 스트링을 모두 추출
        ALL_STRS=$(run_cmd "[U_60_1] Community String 설정값 추출" "grep -v '^#' '$SNMP_CONF' 2>/dev/null | grep -E 'com2sec|rocommunity|rwcommunity' | awk '{print (\$1==\"com2sec\"?\$4:\$2)}' || echo '미설정'")
        
        if [[ "$ALL_STRS" != "미설정" ]]; then
            VUL_STR_FOUND=""
            for STR in $ALL_STRS; do
                # 1) 기본값(public, private) 체크 또는 2) 길이 체크 (10자리 미만)
                if [[ "$STR" == "public" ]] || [[ "$STR" == "private" ]] || [[ ${#STR} -lt 10 ]]; then
                    U_60_1=1
                    VUL_STR_FOUND="$STR"
                    break
                fi
            done
            
            if [[ $U_60_1 -eq 1 ]]; then
                log_basis "[U_60_1] 취약한 Community String 발견 ($VUL_STR_FOUND): 기본값 사용 또는 10자리 미만" "취약"
            else
                log_basis "[U_60_1] 설정된 Community String의 복잡성이 적절함" "양호"
            fi
        else
            log_basis "[U_60_1] SNMP 설정 파일 내 Community String 설정이 발견되지 않아 양호함" "양호"
        fi
    else
        log_step "[U_60_1] 설정 파일 확인" "ls $SNMP_CONF" "파일 없음"
        log_basis "[U_60_1] SNMP 설정 파일이 존재하지 않아 양호함" "양호"
    fi
else
    # 패키지 미설치 시 로깅
    log_basis "[U_60_1] SNMP 서비스가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 2. 전체 취약 여부 판단
IS_VUL=$U_60_1

# 3. JSON 출력 (원본 구조 및 플래그 명칭 절대 유지)
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-60",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service_management",
    "flag": {
      "U_60_1": $U_60_1
    },
    "timestamp": "$DATE"
  }
}
EOF
