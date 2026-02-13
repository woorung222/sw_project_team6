#!/usr/bin/env bash
set -u

# =========================================================
# U_20 (상) /etc/(x)inetd.conf 파일 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 소유자 root, 권한 600 이하
# - DB 정합성: IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_20"
CATEGORY="file"
IS_AUTO=1

U_20_1=0 # inetd
U_20_2=0 # xinetd
U_20_3=0 # systemd

# 1) [U_20_1] /etc/inetd.conf 점검
if [ -f "/etc/inetd.conf" ]; then
    OWNER=$(stat -c "%U" /etc/inetd.conf)
    PERM=$(stat -c "%a" /etc/inetd.conf)
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        U_20_1=1
    fi
fi

# 2) [U_20_2] /etc/xinetd.conf 및 xinetd.d 점검
X_FILES="/etc/xinetd.conf"
[ -d "/etc/xinetd.d" ] && X_FILES="$X_FILES /etc/xinetd.d"
for target in $X_FILES; do
    if [ -e "$target" ]; then
        if find "$target" -maxdepth 1 -type f \( ! -user root -o -perm /077 \) -print -quit 2>/dev/null | grep -q .; then
            U_20_2=1
            break
        fi
    fi
done

# 3) [U_20_3] /etc/systemd 관련 점검
S_FILES="/etc/systemd/system.conf /etc/systemd/user.conf"
[ -d "/etc/systemd" ] && S_FILES="$S_FILES /etc/systemd"
for target in $S_FILES; do
    if [ -e "$target" ]; then
        if find "$target" -maxdepth 1 -type f \( ! -user root -o -perm /077 \) -print -quit 2>/dev/null | grep -q .; then
            U_20_3=1
            break
        fi
    fi
done

IS_VUL=0
[ "$U_20_1" -eq 1 ] || [ "$U_20_2" -eq 1 ] || [ "$U_20_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_20_1": $U_20_1, "U_20_2": $U_20_2, "U_20_3": $U_20_3 },
    "timestamp": "$DATE"
  }
}
EOF