#!/bin/bash

# [U-35] 공유 서비스 익명 접근 제한
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-35"
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
U_35_1=0; U_35_2=0; U_35_3=0; U_35_4=0; U_35_5=0; IS_VUL=0

# 1. [FTP] 계정 점검 (U_35_1)
FTP_ACC=$(run_cmd "[U_35_1] 익명 FTP 계정 확인" "grep -E '^ftp:|^anonymous:' /etc/passwd")
if [[ -n "$FTP_ACC" ]]; then U_35_1=1; fi
log_basis "[U_35_1] 익명 FTP 계정 존재 여부" "$([[ $U_35_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [vsFTP] 설정 점검 (U_35_2)
VS_CONF="/etc/vsftpd/vsftpd.conf"
[[ ! -f "$VS_CONF" ]] && VS_CONF="/etc/vsftpd.conf"
if [[ -f "$VS_CONF" ]]; then
    VS_RES=$(run_cmd "[U_35_2] vsftpd 익명 허용 설정 확인" "grep -v '^#' '$VS_CONF' | grep -i 'anonymous_enable' | grep -iw 'YES'")
    if [[ -n "$VS_RES" ]]; then U_35_2=1; fi
else
    log_step "[U_35_2] 파일 확인" "ls $VS_CONF" "파일 없음"
fi
log_basis "[U_35_2] vsftpd 익명 접속 허용 여부" "$([[ $U_35_2 -eq 1 ]] && echo '취약' || echo '양호')"

# 3. [ProFTP] 설정 점검 (U_35_3)
PRO_CONF="/etc/proftpd/proftpd.conf"
[[ ! -f "$PRO_CONF" ]] && PRO_CONF="/etc/proftpd.conf"
if [[ -f "$PRO_CONF" ]]; then
    PRO_RES=$(run_cmd "[U_35_3] proftpd 익명 설정 확인" "sed -n '/<Anonymous/,/<\/Anonymous>/p' '$PRO_CONF' 2>/dev/null | grep -vE '^#' | grep -iE 'User|UserAlias'")
    if [[ -n "$PRO_RES" ]]; then U_35_3=1; fi
else
    log_step "[U_35_3] 파일 확인" "ls $PRO_CONF" "파일 없음"
fi
log_basis "[U_35_3] proftpd 익명 접속 설정 여부" "$([[ $U_35_3 -eq 1 ]] && echo '취약' || echo '양호')"

# 4. [NFS] 설정 점검 (U_35_4)
if [[ -f "/etc/exports" ]]; then
    NFS_RES=$(run_cmd "[U_35_4] NFS 익명 옵션 확인" "grep -v '^#' /etc/exports | grep -Ei 'anonuid|anongid'")
    if [[ -n "$NFS_RES" ]]; then U_35_4=1; fi
else
    log_step "[U_35_4] 파일 확인" "ls /etc/exports" "파일 없음"
fi
log_basis "[U_35_4] NFS 익명 접근 옵션 존재 여부" "$([[ $U_35_4 -eq 1 ]] && echo '취약' || echo '양호')"

# 5. [Samba] 설정 점검 (U_35_5)
if [[ -f "/etc/samba/smb.conf" ]]; then
    SMB_RES=$(run_cmd "[U_35_5] Samba 익명 허용 확인" "grep -v '^#' /etc/samba/smb.conf 2>/dev/null | grep -i 'guest ok' | grep -iw 'yes'")
    if [[ -n "$SMB_RES" ]]; then U_35_5=1; fi
else
    log_step "[U_35_5] 파일 확인" "ls /etc/samba/smb.conf" "파일 없음"
fi
log_basis "[U_35_5] Samba 익명 사용자 접근 허용 여부" "$([[ $U_35_5 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_35_1 -eq 1 ]] || [[ $U_35_2 -eq 1 ]] || [[ $U_35_3 -eq 1 ]] || [[ $U_35_4 -eq 1 ]] || [[ $U_35_5 -eq 1 ]]; then IS_VUL=1; fi

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