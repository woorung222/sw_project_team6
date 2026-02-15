#!/usr/bin/env bash
set -u

# =========================================================
# U_21 (상) /etc/(r)syslog.conf 파일 소유자 및 권한 설정 | Ubuntu 24.04
# - 진단 기준: 소유자 root(bin, sys), 권한 640 이하
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_21"
CATEGORY="file"
IS_AUTO=1

U_21_1=0 # syslog.conf
U_21_2=0 # rsyslog.conf

check_perm() {
    local target=$1
    if [ -f "$target" ]; then
        local owner=$(stat -c "%U" "$target")
        local perm=$(stat -c "%a" "$target")
        if [[ "$owner" =~ ^(root|bin|sys)$ ]] && [ "$perm" -le 640 ]; then
            echo 0
        else
            echo 1
        fi
    else
        echo 0
    fi
}

U_21_1=$(check_perm "/etc/syslog.conf")
U_21_2=$(check_perm "/etc/rsyslog.conf")

# syslog-ng.conf 등 추가 파일이 있다면 U_21_1 또는 U_21_2에 합산 가능
[ -f "/etc/syslog-ng.conf" ] && [ "$(check_perm "/etc/syslog-ng.conf")" -eq 1 ] && U_21_1=1

IS_VUL=0
[ "$U_21_1" -eq 1 ] || [ "$U_21_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_21_1": $U_21_1, "U_21_2": $U_21_2 },
    "timestamp": "$DATE"
  }
}
EOF