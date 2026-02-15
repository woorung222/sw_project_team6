#!/usr/bin/env bash
set -u

# =========================================================
# U_54 (중) 암호화되지 않은 FTP 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준 : FTP 서비스 활성화 및 프로세스 구동 여부 점검
# - DB 정합성 : IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_54"
CATEGORY="service"
IS_AUTO=1

U_54_1=0; U_54_2=0; U_54_3=0; U_54_4=0; U_54_5=0

# 1) [U_54_1] inetd 점검
if [ -f "/etc/inetd.conf" ] && grep -v "^#" /etc/inetd.conf | grep -iw "ftp" >/dev/null 2>&1; then
    U_54_1=1
fi

# 2) [U_54_2] xinetd 점검
if [ -d "/etc/xinetd.d" ] && grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iw "ftp" >/dev/null 2>&1; then
    U_54_2=1
fi

# 3) [U_54_3] vsFTP 점검 (Systemd)
if systemctl is-active --quiet vsftpd 2>/dev/null; then
    U_54_3=1
fi

# 4) [U_54_4] ProFTP 점검 (Systemd)
if systemctl is-active --quiet proftpd 2>/dev/null; then
    U_54_4=1
fi

# 5) [U_54_5] 프로세스 점검 (실제 구동 여부 전수 확인)
if ps -ef | grep -v grep | grep -iE "vsftpd|proftpd|in.ftpd" | grep -q .; then
    U_54_5=1
fi

IS_VUL=0
[ "$U_54_1" -eq 1 ] || [ "$U_54_2" -eq 1 ] || [ "$U_54_3" -eq 1 ] || [ "$U_54_4" -eq 1 ] || [ "$U_54_5" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_54_1": $U_54_1, "U_54_2": $U_54_2, "U_54_3": $U_54_3, "U_54_4": $U_54_4, "U_54_5": $U_54_5 },
    "timestamp": "$DATE"
  }
}
EOF