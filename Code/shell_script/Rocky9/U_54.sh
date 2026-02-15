#!/bin/bash

# [U-54] 암호화되지 않은 FTP 서비스 비활성화 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : FTP 관련 서비스(inetd, xinetd, vsftpd, proftpd)가 모두 비활성화된 경우 양호
# DB 정합성 : IS_AUTO=1 (자동화 스크립트 적용 가능)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_54_1=0; U_54_2=0; U_54_3=0; U_54_4=0; U_54_5=0
IS_VUL=0
IS_AUTO=1 

# 1. [U_54_1] inetd 점검
if [ -f "/etc/inetd.conf" ] && grep -v "^#" /etc/inetd.conf | grep -iw "ftp" >/dev/null 2>&1; then
    U_54_1=1
fi

# 2. [U_54_2] xinetd 점검
if [ -f "/etc/xinetd.d/ftp" ] && grep -i "disable" /etc/xinetd.d/ftp | grep -iw "no" >/dev/null 2>&1; then
    U_54_2=1
fi

# 3. [U_54_3] vsFTPd 서비스 점검
if systemctl is-active --quiet vsftpd 2>/dev/null; then
    U_54_3=1
fi

# 4. [U_54_4] ProFTPd 서비스 점검
if systemctl is-active --quiet proftpd 2>/dev/null; then
    U_54_4=1
fi

# 5. [U_54_5] 프로세스 점검
if ps -ef | grep -v "grep" | grep -iE "vsftpd|proftpd|in.ftpd" >/dev/null 2>&1; then
    U_54_5=1
fi

[ "$U_54_1" -eq 1 ] || [ "$U_54_2" -eq 1 ] || [ "$U_54_3" -eq 1 ] || [ "$U_54_4" -eq 1 ] || [ "$U_54_5" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-54",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_54_1": $U_54_1, "U_54_2": $U_54_2, "U_54_3": $U_54_3, "U_54_4": $U_54_4, "U_54_5": $U_54_5 },
    "timestamp": "$DATE"
  }
}
EOF