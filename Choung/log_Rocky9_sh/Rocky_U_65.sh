#!/bin/bash

# [U-65] NTP 및 시각 동기화 설정
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-65"
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
U_65_1=0; U_65_2=0; U_65_3=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 패키지 설치 확인 (로그 기록)
PKG_C=$(run_cmd "[65] chrony 패키지 확인" "rpm -qa | grep '^chrony-[0-9]' || echo '안 깔려 있음'")
PKG_N=$(run_cmd "[65] ntp 패키지 확인" "rpm -qa | grep '^ntp-[0-9]' || echo '안 깔려 있음'")

# 1. [U_65_1] 패키지 미설치 점검
if [[ "$PKG_C" == "안 깔려 있음" ]] && [[ "$PKG_N" == "안 깔려 있음" ]]; then
    U_65_1=1
    log_basis "[U_65_1] 시간 동기화 패키지(chrony, ntp)가 모두 설치되어 있지 않음" "취약"
else
    log_basis "[U_65_1] 시간 동기화 패키지 확인 완료" "양호"
fi

# 2. [U_65_2] Chrony 점검
if [[ "$PKG_C" != "안 깔려 있음" ]]; then
    C_ACT=$(run_cmd "[U_65_2] chronyd 활성 상태 확인" "systemctl is-active chronyd 2>/dev/null || echo 'inactive'")
    C_SRV=$(run_cmd "[U_65_2] chrony 서버 설정 확인" "grep -E '^server|^pool' /etc/chrony.conf || echo '없음'")
    
    if [[ "$C_ACT" != "active" ]] || [[ "$C_SRV" == "없음" ]]; then
        U_65_2=1
        log_basis "[U_65_2] chronyd 서비스 비활성 또는 서버 설정 누락" "취약"
    else
        log_basis "[U_65_2] chronyd 서비스 및 설정 양호" "양호"
    fi
else
    log_basis "[U_65_2] chrony 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 3. [U_65_3] NTP 점검
if [[ "$PKG_N" != "안 깔려 있음" ]]; then
    N_ACT=$(run_cmd "[U_65_3] ntpd 활성 상태 확인" "systemctl is-active ntpd 2>/dev/null || echo 'inactive'")
    N_SRV=$(run_cmd "[U_65_3] ntp 서버 설정 확인" "grep '^server' /etc/ntp.conf || echo '없음'")
    
    if [[ "$N_ACT" != "active" ]] || [[ "$N_SRV" == "없음" ]]; then
        U_65_3=1
        log_basis "[U_65_3] ntpd 서비스 비활성 또는 서버 설정 누락" "취약"
    else
        log_basis "[U_65_3] ntpd 서비스 및 설정 양호" "양호"
    fi
else
    log_basis "[U_65_3] ntp 패키지가 설치되어 있지 않음 (안 깔려 있음)" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_65_1 -eq 1 || $U_65_2 -eq 1 || $U_65_3 -eq 1 ]]; then IS_VUL=1; fi

# JSON 출력
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-65",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "log",
    "flag": {
      "U_65_1": $U_65_1,
      "U_65_2": $U_65_2,
      "U_65_3": $U_65_3
    },
    "timestamp": "$DATE"
  }
}
EOF