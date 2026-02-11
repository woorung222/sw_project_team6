#!/bin/bash

# [U-52] 원격 접속 시 Telnet 프로토콜 사용 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-52"
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
U_52_1=0; U_52_2=0; U_52_3=0; U_52_4=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_52_1] inetd 점검
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_CHECK=$(run_cmd "[U_52_1] inetd.conf Telnet 검색" "grep -i 'telnet' /etc/inetd.conf | grep -v '^#' || echo 'none'")
    if [[ "$INETD_CHECK" != "none" ]]; then
        U_52_1=1
        log_basis "[U_52_1] inetd.conf 내 Telnet 서비스 활성화: $INETD_CHECK" "취약"
    else
        log_basis "[U_52_1] inetd.conf 내 Telnet 설정 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_52_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_52_1] inetd.conf 파일 미존재" "양호"
fi

# 2. [U_52_2] xinetd 점검
if [[ -f "/etc/xinetd.d/telnet" ]]; then
    XINETD_CHECK=$(run_cmd "[U_52_2] xinetd Telnet disable 검색" "grep -i 'disable' /etc/xinetd.d/telnet | grep -i 'no' || echo 'none'")
    if [[ "$XINETD_CHECK" != "none" ]]; then
        U_52_2=1
        log_basis "[U_52_2] xinetd.d/telnet 활성화 설정 발견: $XINETD_CHECK" "취약"
    else
        log_basis "[U_52_2] xinetd.d/telnet 활성화 설정 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_52_2] xinetd Telnet 파일 확인" "ls /etc/xinetd.d/telnet 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_52_2] xinetd Telnet 설정 파일 미존재" "양호"
fi

# 3. [U_52_3] systemd 점검
SYSTEMD_CHECK=$(run_cmd "[U_52_3] systemd Telnet 소켓 상태" "systemctl list-units --type=socket 2>/dev/null | grep -i 'telnet' | grep 'active' || echo 'none'")
if [[ "$SYSTEMD_CHECK" != "none" ]]; then
    U_52_3=1
    log_basis "[U_52_3] Systemd Telnet 소켓 활성화: $SYSTEMD_CHECK" "취약"
else
    log_basis "[U_52_3] Systemd Telnet 소켓 비활성" "양호"
fi

# 4. [U_52_4] Process 점검
PROC_CHECK=$(run_cmd "[U_52_4] Telnet 프로세스 검색" "ps -ef | grep -v 'grep' | grep -i 'telnet' || echo 'none'")
if [[ "$PROC_CHECK" != "none" ]]; then
    U_52_4=1
    log_basis "[U_52_4] Telnet 프로세스 실행 중: $PROC_CHECK" "취약"
else
    log_basis "[U_52_4] Telnet 프로세스 미발견" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_52_1 -eq 1 || $U_52_2 -eq 1 || $U_52_3 -eq 1 || $U_52_4 -eq 1 ]]; then
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
      "U_52_1": $U_52_1,
      "U_52_2": $U_52_2,
      "U_52_3": $U_52_3,
      "U_52_4": $U_52_4
    },
    "timestamp": "$DATE"
  }
}
EOF