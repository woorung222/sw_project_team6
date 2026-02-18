#!/usr/bin/env bash
set -u

# =========================================================
# U_44 (상) tftp, talk 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준: tftp, talk, ntalk 서비스 활성화 여부 점검
# - DB 정합성: IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_44"
CATEGORY="service"
IS_AUTO=1

U_44_1=0; U_44_2=0; U_44_3=0
TARGETS="tftp|talk|ntalk"

# 1) [U_44_1] inetd 점검
if [ -f "/etc/inetd.conf" ] && grep -v "^#" /etc/inetd.conf | grep -iE "$TARGETS" | grep -q .; then
    U_44_1=1
fi

# 2) [U_44_2] xinetd 점검
if [ -d "/etc/xinetd.d" ] && grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$TARGETS" | grep -q .; then
    U_44_2=1
fi

# 3) [U_44_3] systemd 및 프로세스 점검
if systemctl list-units --type service,socket --all 2>/dev/null | grep -E "$TARGETS" | grep -q "active"; then
    U_44_3=1
elif ps -ef | grep -v grep | grep -iE "tftpd|talkd|ntalkd" | grep -q .; then
    U_44_3=1
fi

IS_VUL=0
[ "$U_44_1" -eq 1 ] || [ "$U_44_2" -eq 1 ] || [ "$U_44_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_44_1": $U_44_1, "U_44_2": $U_44_2, "U_44_3": $U_44_3 },
    "timestamp": "$DATE"
  }
}
EOF