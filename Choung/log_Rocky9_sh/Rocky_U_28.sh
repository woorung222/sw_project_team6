#!/bin/bash

# [U-28] 허용할 호스트에 대한 접속 IP주소 제한 및 포트 제한 설정 여부
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-28"
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

# 초기 상태 설정
U_28_1=1; U_28_2=1; U_28_3=1; U_28_4=1; IS_VUL=1

# --- [U_28_1] TCP Wrapper 점검 ---
HOSTS_DENY="/etc/hosts.deny"
HOSTS_ALLOW="/etc/hosts.allow"

# 파일 존재 여부 확인부터 run_cmd로 기록
FILE_CHECK=$(run_cmd "[U_28_1] 설정 파일 존재 확인" "ls $HOSTS_DENY $HOSTS_ALLOW 2>/dev/null")

if [ -f "$HOSTS_DENY" ] && [ -f "$HOSTS_ALLOW" ]; then
    DENY_OUT=$(run_cmd "[U_28_1] hosts.deny 'ALL:ALL' 설정 확인" "grep -i 'ALL:ALL' $HOSTS_DENY | grep -v '^#'")
    ALLOW_OUT=$(run_cmd "[U_28_1] hosts.allow 허용 정책 확인" "grep -v '^#' $HOSTS_ALLOW | grep -v '^$'")
    
    if [ -n "$DENY_OUT" ] && [ -n "$ALLOW_OUT" ]; then
        U_28_1=0
        log_basis "[U_28_1] TCP Wrapper 설정 양호 (deny ALL:ALL 및 allow 리스트 존재)" "양호"
    else
        U_28_1=1
        log_basis "[U_28_1] TCP Wrapper 설정 미흡" "취약"
    fi
else
    U_28_1=1
    log_basis "[U_28_1] TCP Wrapper 관련 설정 파일(/etc/hosts.deny 등)이 존재하지 않음" "취약"
fi

# --- [U_28_2] Iptables 점검 ---
# 설치 여부 확인 커맨드 기록
IPT_INSTALLED=$(run_cmd "[U_28_2] iptables 설치 확인" "which iptables 2>/dev/null")

if [ -n "$IPT_INSTALLED" ]; then
    IPT_RULES=$(run_cmd "[U_28_2] iptables 룰 존재 여부 확인" "iptables -L -n | grep -v '^Chain' | grep -v '^target' | grep -v '^$'")
    if [ -n "$IPT_RULES" ]; then
        U_28_2=0
        log_basis "[U_28_2] iptables 룰이 등록되어 통제 중임" "양호"
    else
        U_28_2=1
        log_basis "[U_28_2] iptables 룰이 존재하지 않음" "취약"
    fi
else
    U_28_2=1
    log_basis "[U_28_2] iptables 명령어가 시스템에 존재하지 않음" "취약"
fi

# --- [U_28_3] Firewalld 점검 ---
FW_STATUS=$(run_cmd "[U_28_3] firewalld 서비스 활성화 상태 확인" "systemctl is-active firewalld")
if [ "$FW_STATUS" == "active" ]; then
    U_28_3=0
    log_basis "[U_28_3] firewalld 서비스가 활성화(active) 되어 있음" "양호"
else
    U_28_3=1
    log_basis "[U_28_3] firewalld 서비스가 비활성화 상태임" "취약"
fi

# --- [U_28_4] UFW 점검 ---
# [수정] UFW 설치 여부 확인 과정을 run_cmd로 기록하여 누락 방지
UFW_INSTALLED=$(run_cmd "[U_28_4] ufw 설치 확인" "which ufw 2>/dev/null")

if [ -n "$UFW_INSTALLED" ]; then
    UFW_OUT=$(run_cmd "[U_28_4] ufw status 상세 확인" "ufw status")
    if echo "$UFW_OUT" | grep -qi "Status: active"; then
        U_28_4=0
        log_basis "[U_28_4] UFW가 활성화(active) 되어 있음" "양호"
    else
        U_28_4=1
        log_basis "[U_28_4] UFW가 비활성화 상태임" "취약"
    fi
else
    # 설치되지 않았을 경우에도 basis 로그를 남김
    U_28_4=1
    log_basis "[U_28_4] UFW 명령어가 시스템에 존재하지 않음" "취약"
fi

# --- 종합 판단 ---
if [ $U_28_1 -eq 0 ] || [ $U_28_2 -eq 0 ] || [ $U_28_3 -eq 0 ] || [ $U_28_4 -eq 0 ]; then
    IS_VUL=0
    log_basis "[U-28 종합] 하나 이상의 네트워크 접근 제어 도구가 설정되어 있음" "양호"
else
    IS_VUL=1
    log_basis "[U-28 종합] 모든 네트워크 접근 제어 설정이 확인되지 않음" "취약"
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-28",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_28_1": $U_28_1,
      "U_28_2": $U_28_2,
      "U_28_3": $U_28_3,
      "U_28_4": $U_28_4
    },
    "timestamp": "$DATE"
  }
}
EOF