#!/bin/bash

# [U-44] tftp, talk, ntalk 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-44"
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
U_44_1=0; U_44_2=0; U_44_3=0; IS_VUL=0

# 점검 서비스 리스트
TFTP_TALK_SERVICES="tftp|talk|ntalk"

# --- 점검 로직 시작 ---

# 1. [U_44_1] inetd.conf 설정 확인
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_CHECK=$(run_cmd "[U_44_1] inetd.conf 내 서비스 확인" "grep -v '^#' /etc/inetd.conf | grep -iE \"$TFTP_TALK_SERVICES\" || echo 'none'")
    if [[ "$INETD_CHECK" != "none" ]]; then
        U_44_1=1
        log_basis "[U_44_1] inetd.conf에 tftp/talk/ntalk 서비스 활성화" "취약"
    else
        log_basis "[U_44_1] inetd.conf에 관련 서비스 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_44_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '없음'")
    log_basis "[U_44_1] inetd.conf 파일 미존재" "양호"
fi

# 2. [U_44_2] xinetd.d 설정 확인
if [[ -d "/etc/xinetd.d" ]]; then
    XINETD_CHECK=$(run_cmd "[U_44_2] xinetd.d 내 서비스 확인" "grep -rEi 'disable.*=.*no' /etc/xinetd.d/ 2>/dev/null | grep -iE \"$TFTP_TALK_SERVICES\" || echo 'none'")
    if [[ "$XINETD_CHECK" != "none" ]]; then
        U_44_2=1
        log_basis "[U_44_2] xinetd 설정에 tftp/talk/ntalk 서비스 활성화" "취약"
    else
        log_basis "[U_44_2] xinetd 설정에 관련 서비스 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_44_2] xinetd.d 디렉토리 확인" "ls -d /etc/xinetd.d 2>/dev/null || echo '없음'")
    log_basis "[U_44_2] xinetd.d 디렉토리 미존재" "양호"
fi

# 3. [U_44_3] Systemd 서비스 유닛 확인
SYSTEMD_CHECK=$(run_cmd "[U_44_3] systemd 서비스 확인" "systemctl list-unit-files 2>/dev/null | grep -iE \"$TFTP_TALK_SERVICES\" | grep 'enabled' || echo 'none'")

if [[ "$SYSTEMD_CHECK" != "none" ]]; then
    U_44_3=1
    log_basis "[U_44_3] systemd에 tftp/talk/ntalk 서비스 enabled 상태" "취약"
else
    log_basis "[U_44_3] systemd에 관련 서비스 활성화되지 않음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_44_1 -eq 1 || $U_44_2 -eq 1 || $U_44_3 -eq 1 ]]; then
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
      "U_44_1": $U_44_1,
      "U_44_2": $U_44_2,
      "U_44_3": $U_44_3
    },
    "timestamp": "$DATE"
  }
}
EOF
