#!/bin/bash

# [U-54] 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# 대상 : Ubuntu 24.04

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-54"
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
U_54_1=0; U_54_2=0; U_54_3=0; U_54_4=0; IS_VUL=0

# --- 점검 로직 수행 ---

# 1. [U_54_1] inetd 점검
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_FTP=$(run_cmd "[U_54_1] inetd FTP 설정 확인" "grep -i 'ftp' /etc/inetd.conf | grep -v '^#' || echo 'none'")
    if [[ "$INETD_FTP" != "none" ]]; then
        U_54_1=1
        log_basis "[U_54_1] inetd.conf FTP 활성화: $INETD_FTP" "취약"
    else
        log_basis "[U_54_1] inetd.conf FTP 설정 없음" "양호"
    fi
else
    TMP=$(run_cmd "[U_54_1] inetd.conf 파일 확인" "ls /etc/inetd.conf 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_54_1] inetd.conf 파일 미존재" "양호"
fi

# 2. [U_54_2] xinetd 점검
if [[ -f "/etc/xinetd.d/ftp" ]]; then
    XINETD_FTP=$(run_cmd "[U_54_2] xinetd FTP 설정 확인" "grep -i 'disable' /etc/xinetd.d/ftp | grep -i 'no' || echo 'none'")
    if [[ "$XINETD_FTP" != "none" ]]; then
        U_54_2=1
        log_basis "[U_54_2] xinetd FTP 활성화: $XINETD_FTP" "취약"
    else
        log_basis "[U_54_2] xinetd FTP 비활성화" "양호"
    fi
else
    TMP=$(run_cmd "[U_54_2] xinetd FTP 설정 확인" "ls /etc/xinetd.d/ftp 2>/dev/null || echo '파일 미존재'")
    log_basis "[U_54_2] xinetd FTP 설정 파일 미존재" "양호"
fi

# 3. [U_54_3] vsFTP 점검
VSFTP_SVC=$(run_cmd "[U_54_3] vsFTPd 서비스 확인" "systemctl list-units --type=service 2>/dev/null | grep 'vsftpd' || echo 'none'")
if [[ "$VSFTP_SVC" != "none" ]]; then
    U_54_3=1
    log_basis "[U_54_3] vsFTPd 서비스 활성화: $VSFTP_SVC" "취약"
else
    log_basis "[U_54_3] vsFTPd 서비스 미발견" "양호"
fi

# 4. [U_54_4] ProFTP 점검
PROFTP_SVC=$(run_cmd "[U_54_4] ProFTP 서비스 확인" "systemctl list-units --type=service 2>/dev/null | grep 'proftp' || echo 'none'")
if [[ "$PROFTP_SVC" != "none" ]]; then
    U_54_4=1
    log_basis "[U_54_4] ProFTP 서비스 활성화: $PROFTP_SVC" "취약"
else
    log_basis "[U_54_4] ProFTP 서비스 미발견" "양호"
fi

# 최종 취약 여부 판단
if [[ $U_54_1 -eq 1 || $U_54_2 -eq 1 || $U_54_3 -eq 1 || $U_54_4 -eq 1 ]]; then
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
      "U_54_1": $U_54_1,
      "U_54_2": $U_54_2,
      "U_54_3": $U_54_3,
      "U_54_4": $U_54_4
    },
    "timestamp": "$DATE"
  }
}
EOF
