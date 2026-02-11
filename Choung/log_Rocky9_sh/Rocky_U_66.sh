#!/bin/bash

# [U-66] 정책에 따른 시스템 로깅 설정
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-66"
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
U_66_1=0; U_66_2=0; U_66_3=0; U_66_4=0; U_66_5=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. [U_66_1] 패키지 및 서비스 상태 점검
P_CHK=$(run_cmd "[U_66_1] rsyslog 패키지 설치 확인" "rpm -qa | grep '^rsyslog-[0-9]' || echo '안 깔려 있음'")
S_ACT=$(run_cmd "[U_66_1] rsyslog 서비스 활성 상태 확인" "systemctl is-active rsyslog 2>/dev/null || echo 'inactive'")

if [[ "$P_CHK" == "안 깔려 있음" ]] || [[ "$S_ACT" != "active" ]]; then
    U_66_1=1
    log_basis "[U_66_1] rsyslog 패키지 미설치 또는 서비스 비활성화" "취약"
else
    log_basis "[U_66_1] rsyslog 서비스 활성화 확인" "양호"
fi

# 2. 설정 파일 점검
if [[ -f "/etc/rsyslog.conf" ]]; then
    # 2-1. Secure 로그 (U_66_2)
    if ! run_cmd "[U_66_2] authpriv 로그 설정(/var/log/secure) 확인" "grep -v '^#' /etc/rsyslog.conf | grep -E 'authpriv\.\*[[:space:]].*\/var\/log\/secure'"; then
        U_66_2=1
        log_basis "[U_66_2] secure 로그 설정 미흡" "취약"
    else
        log_basis "[U_66_2] secure 로그 설정 양호" "양호"
    fi

    # 2-2. Messages 로그 (U_66_3)
    if ! run_cmd "[U_66_3] messages 로그 설정(/var/log/messages) 확인" "grep -v '^#' /etc/rsyslog.conf | grep -E '\*\.info.*\/var\/log\/messages'"; then
        U_66_3=1
        log_basis "[U_66_3] messages 로그 설정 미흡" "취약"
    else
        log_basis "[U_66_3] messages 로그 설정 양호" "양호"
    fi

    # 2-3. Cron 로그 (U_66_4)
    if ! run_cmd "[U_66_4] cron 로그 설정(/var/log/cron) 확인" "grep -v '^#' /etc/rsyslog.conf | grep -E 'cron\.\*.*\/var\/log\/cron'"; then
        U_66_4=1
        log_basis "[U_66_4] cron 로그 설정 미흡" "취약"
    else
        log_basis "[U_66_4] cron 로그 설정 양호" "양호"
    fi

    # 2-4. Maillog (U_66_5)
    if ! run_cmd "[U_66_5] maillog 로그 설정(/var/log/maillog) 확인" "grep -v '^#' /etc/rsyslog.conf | grep -E 'mail\.\*.*-?\/var\/log\/maillog'"; then
        U_66_5=1
        log_basis "[U_66_5] maillog 로그 설정 미흡" "취약"
    else
        log_basis "[U_66_5] maillog 로그 설정 양호" "양호"
    fi
else
    log_step "[Config] 설정 파일 확인" "ls /etc/rsyslog.conf" "파일 없음"
    # 설정 파일이 없으면 서비스 점검 항목 외 모든 플래그 취약 처리
    U_66_2=1; U_66_3=1; U_66_4=1; U_66_5=1
    log_basis "[U_66_2~5] rsyslog.conf 파일이 존재하지 않아 로그 설정 점검 불가" "취약"
fi

if [[ $U_66_1 -eq 1 || $U_66_2 -eq 1 || $U_66_3 -eq 1 || $U_66_4 -eq 1 || $U_66_5 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-66",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "log",
    "flag": {
      "U_66_1": $U_66_1,
      "U_66_2": $U_66_2,
      "U_66_3": $U_66_3, 
      "U_66_4": $U_66_4, 
      "U_66_5": $U_66_5
    },
    "timestamp": "$DATE"
  }
}
EOF