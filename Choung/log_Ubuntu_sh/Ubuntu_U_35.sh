#!/bin/bash

# [U-35] 주요 파일 전송 서비스 익명 접속 및 취약 설정 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-35"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_35_1=0; U_35_2=0; U_35_3=0; U_35_4=0; U_35_5=0; IS_VUL=0

# 1. [U_35_1] 기본 FTP 서비스 점검 (inetd/xinetd)
FTP_CHECK=$(run_cmd "[U_35_1] inetd/xinetd 내 ftp 설정 확인" "grep -rE 'ftp' /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null | grep -v '^#' || echo 'none'")
if [[ "$FTP_CHECK" != "none" ]]; then
    U_35_1=1
    log_basis "[U_35_1] inetd/xinetd를 통한 FTP 서비스 활성화됨" "취약"
else
    log_basis "[U_35_1] inetd/xinetd FTP 서비스 미발견" "양호"
fi

# 2. [U_35_2] vsFTPd 익명 접속 점검
VSFTP_CONF=""
if [[ -f "/etc/vsftpd.conf" ]]; then VSFTP_CONF="/etc/vsftpd.conf"; 
elif [[ -f "/etc/vsftpd/vsftpd.conf" ]]; then VSFTP_CONF="/etc/vsftpd/vsftpd.conf"; fi

if [[ -n "$VSFTP_CONF" ]]; then
    VS_ANON=$(run_cmd "[U_35_2] vsFTPd 익명 접속 설정 확인" "grep -i 'anonymous_enable=YES' $VSFTP_CONF | grep -v '^#' || echo 'none'")
    if [[ "$VS_ANON" != "none" ]]; then
        U_35_2=1
        log_basis "[U_35_2] vsFTPd 익명 접속(anonymous_enable=YES) 허용됨" "취약"
    else
        log_basis "[U_35_2] vsFTPd 익명 접속 비활성화됨" "양호"
    fi
else
    log_basis "[U_35_2] vsFTPd 설정 파일 없음" "양호"
fi

# 3. [U_35_3] ProFTPd 익명 접속 점검
if [[ -f "/etc/proftpd/proftpd.conf" ]]; then
    PRO_ANON=$(run_cmd "[U_35_3] ProFTPd 익명 접속 설정 확인" "grep -i '<Anonymous' /etc/proftpd/proftpd.conf | grep -v '^#' || echo 'none'")
    if [[ "$PRO_ANON" != "none" ]]; then
        U_35_3=1
        log_basis "[U_35_3] ProFTPd 익명 접속(<Anonymous>) 설정 발견" "취약"
    else
        log_basis "[U_35_3] ProFTPd 익명 접속 설정 없음" "양호"
    fi
else
    log_basis "[U_35_3] ProFTPd 설정 파일 없음" "양호"
fi

# 4. [U_35_4] NFS 공유 설정 점검
if [[ -f "/etc/exports" ]]; then
    NFS_VULN=$(run_cmd "[U_35_4] NFS 취약 옵션 확인" "grep -E '(insecure|all_squash|no_root_squash|anonuid|anongid)' /etc/exports | grep -v '^#' || echo 'none'")
    if [[ "$NFS_VULN" != "none" ]]; then
        U_35_4=1
        log_basis "[U_35_4] NFS 설정 파일에 취약한 옵션(insecure/root_squash 등) 존재" "취약"
    else
        log_basis "[U_35_4] NFS 취약 옵션 미발견" "양호"
    fi
else
    log_basis "[U_35_4] /etc/exports 파일 없음" "양호"
fi

# 5. [U_35_5] Samba Guest 접속 점검
if [[ -f "/etc/samba/smb.conf" ]]; then
    SMB_GUEST=$(run_cmd "[U_35_5] Samba Guest 설정 확인" "grep -Ei '(guest ok = yes|map to guest = bad user|public = yes)' /etc/samba/smb.conf | grep -v '^#' || echo 'none'")
    if [[ "$SMB_GUEST" != "none" ]]; then
        U_35_5=1
        log_basis "[U_35_5] Samba Guest 접속 허용 설정 발견" "취약"
    else
        log_basis "[U_35_5] Samba Guest 접속 설정 없음" "양호"
    fi
else
    log_basis "[U_35_5] Samba 설정 파일 없음" "양호"
fi

if [[ $U_35_1 -eq 1 || $U_35_2 -eq 1 || $U_35_3 -eq 1 || $U_35_4 -eq 1 || $U_35_5 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-35",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_35_1": $U_35_1,
      "U_35_2": $U_35_2,
      "U_35_3": $U_35_3,
      "U_35_4": $U_35_4,
      "U_35_5": $U_35_5
    },
    "timestamp": "$DATE"
  }
}
EOF
