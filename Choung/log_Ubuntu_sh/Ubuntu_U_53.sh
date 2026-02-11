#!/bin/bash

# [U-53] FTP 서비스 접속 배너를 통한 불필요한 정보 노출 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-53"
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
U_53_1=0; U_53_2=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_53_1] vsFTP 점검
VSFTP_CONF=""
if [[ -f "/etc/vsftpd.conf" ]]; then VSFTP_CONF="/etc/vsftpd.conf";
elif [[ -f "/etc/vsftpd/vsftpd.conf" ]]; then VSFTP_CONF="/etc/vsftpd/vsftpd.conf"; fi

if [[ -n "$VSFTP_CONF" ]]; then
    BANNER_CHECK=$(run_cmd "[U_53_1] vsFTPd 배너 설정 확인" "grep -i 'ftpd_banner' \"$VSFTP_CONF\" | grep -v '^#' || echo 'none'")
    
    if [[ "$BANNER_CHECK" == "none" ]]; then
        U_53_1=1
        log_basis "[U_53_1] vsFTPd 배너 설정 미발견" "취약"
    else
        log_basis "[U_53_1] vsFTPd 배너 설정 확인: $BANNER_CHECK" "양호"
    fi
else
    TMP=$(run_cmd "[U_53_1] vsFTPd 설정 파일 확인" "ls /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_53_1] vsFTPd 설정 파일 없음" "양호"
fi

# 2. [U_53_2] ProFTP 점검
PROFTP_CONF=""
if [[ -f "/etc/proftpd.conf" ]]; then PROFTP_CONF="/etc/proftpd.conf";
elif [[ -f "/etc/proftpd/proftpd.conf" ]]; then PROFTP_CONF="/etc/proftpd/proftpd.conf"; fi

if [[ -n "$PROFTP_CONF" ]]; then
    IDENT_CHECK=$(run_cmd "[U_53_2] ProFTP ServerIdent 확인" "grep -i 'ServerIdent' \"$PROFTP_CONF\" | grep -v '^#' || echo 'none'")
    
    if [[ "$IDENT_CHECK" == "none" ]]; then
        U_53_2=1
        log_basis "[U_53_2] ServerIdent 설정 없음 (기본값 노출)" "취약"
    else
        if echo "$IDENT_CHECK" | grep -iq "on" && ! echo "$IDENT_CHECK" | grep -q "\""; then
            U_53_2=1
            log_basis "[U_53_2] ServerIdent 'on'이나 사용자 메시지 없음: $IDENT_CHECK" "취약"
        else
            log_basis "[U_53_2] ServerIdent 설정 양호: $IDENT_CHECK" "양호"
        fi
    fi
else
    TMP=$(run_cmd "[U_53_2] ProFTP 설정 파일 확인" "ls /etc/proftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_53_2] ProFTP 설정 파일 없음" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_53_1 -eq 1 || $U_53_2 -eq 1 ]]; then
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
      "U_53_1": $U_53_1,
      "U_53_2": $U_53_2
    },
    "timestamp": "$DATE"
  }
}
EOF