#!/usr/bin/env bash
set -u

# =========================================================
# U_52 (중) Telnet 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준 : Telnet 프로토콜 사용 여부(inetd, xinetd, systemd, process)
# - DB 정합성 : IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_52"
CATEGORY="service"
IS_AUTO=1

U_52_1=0; U_52_2=0; U_52_3=0; U_52_4=0

# 1) [U_52_1] inetd 점검
if [ -f "/etc/inetd.conf" ] && grep -v "^#" /etc/inetd.conf | grep -iw "telnet" >/dev/null 2>&1; then
    U_52_1=1
fi

# 2) [U_52_2] xinetd 점검
if [ -d "/etc/xinetd.d" ] && grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iw "telnet" >/dev/null 2>&1; then
    U_52_2=1
fi

# 3) [U_52_3] systemd 점검
if systemctl list-units --type=socket,service --all 2>/dev/null | grep -i "telnet" | grep -q "active"; then
    U_52_3=1
fi

# 4) [U_52_4] 프로세스 점검
if ps -ef | grep -v grep | grep -iE "telnetd|in.telnetd" | grep -q .; then
    U_52_4=1
fi

IS_VUL=0
[ "$U_52_1" -eq 1 ] || [ "$U_52_2" -eq 1 ] || [ "$U_52_3" -eq 1 ] || [ "$U_52_4" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_52_1": $U_52_1, "U_52_2": $U_52_2, "U_52_3": $U_52_3, "U_52_4": $U_52_4 },
    "timestamp": "$DATE"
  }
}
EOF