#!/bin/bash

# [U-66] 가이드 사례에 따른 시스템 로깅 설정 적정성 점검
# 대상 : Ubuntu 24.04

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

# --- 점검 로직 수행 ---

# [U_66_1] rsyslog 설치 및 활성 확인
CHECK_RSYSLOG=$(run_cmd "[U_66_1] rsyslogd 명령 확인" "command -v rsyslogd || echo 'none'")
RSYSLOG_ACT=$(run_cmd "[U_66_1] rsyslog 서비스 상태" "systemctl is-active rsyslog 2>/dev/null || echo 'inactive'")

if [[ "$CHECK_RSYSLOG" == "none" ]] || [[ "$RSYSLOG_ACT" != "active" ]]; then
    U_66_1=1
    log_basis "[U_66_1] rsyslog 미설치 또는 비활성화 (Cmd:$CHECK_RSYSLOG, Status:$RSYSLOG_ACT)" "취약"
    
    # 서비스가 없으면 하위 설정 점검 불가 -> 모두 취약 처리
    U_66_2=1; U_66_3=1; U_66_4=1; U_66_5=1
else
    U_66_1=0
    log_basis "[U_66_1] rsyslog 서비스 동작 중" "양호"
    
    CONF_FILES="/etc/rsyslog.conf /etc/rsyslog.d/"
    
    # [U_66_2] authpriv.* 확인
    AUTH_CHECK=$(run_cmd "[U_66_2] authpriv 설정 검색" "grep -rE 'authpriv\.\*' $CONF_FILES 2>/dev/null | grep -vE '^\s*#' || echo 'none'")
    if [[ "$AUTH_CHECK" == "none" ]]; then
        U_66_2=1
        log_basis "[U_66_2] authpriv.* 로그 설정 미발견" "취약"
    else
        log_basis "[U_66_2] authpriv 설정됨: $AUTH_CHECK" "양호"
    fi

    # [U_66_3] *.info 확인
    INFO_CHECK=$(run_cmd "[U_66_3] *.info 설정 검색" "grep -rE '\*\.info' $CONF_FILES 2>/dev/null | grep -vE '^\s*#' || echo 'none'")
    if [[ "$INFO_CHECK" == "none" ]]; then
        U_66_3=1
        log_basis "[U_66_3] *.info 로그 설정 미발견" "취약"
    else
        log_basis "[U_66_3] *.info 설정됨: $INFO_CHECK" "양호"
    fi

    # [U_66_4] cron.* 확인
    CRON_CHECK=$(run_cmd "[U_66_4] cron.* 설정 검색" "grep -rE 'cron\.\*' $CONF_FILES 2>/dev/null | grep -vE '^\s*#' || echo 'none'")
    if [[ "$CRON_CHECK" == "none" ]]; then
        U_66_4=1
        log_basis "[U_66_4] cron.* 로그 설정 미발견" "취약"
    else
        log_basis "[U_66_4] cron 설정됨: $CRON_CHECK" "양호"
    fi

    # [U_66_5] mail.* 확인
    MAIL_CHECK=$(run_cmd "[U_66_5] mail.* 설정 검색" "grep -rE 'mail\.\*' $CONF_FILES 2>/dev/null | grep -vE '^\s*#' || echo 'none'")
    if [[ "$MAIL_CHECK" == "none" ]]; then
        U_66_5=1
        log_basis "[U_66_5] mail.* 로그 설정 미발견" "취약"
    else
        log_basis "[U_66_5] mail 설정됨: $MAIL_CHECK" "양호"
    fi
fi

# 최종 취약 여부 판단
if [[ $U_66_1 -eq 1 || $U_66_2 -eq 1 || $U_66_3 -eq 1 || $U_66_4 -eq 1 || $U_66_5 -eq 1 ]]; then
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
