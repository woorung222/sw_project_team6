#!/usr/bin/env bash
set -u

# =========================================================
# U_27 (상) $HOME/.rhosts, hosts.equiv 사용 금지 | Ubuntu 24.04
# - 진단 기준: 소유자(root/계정), 권한(600), '+' 설정 제거
# - DB 정합성: IS_AUTO=0
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_27"
CATEGORY="file"
IS_AUTO=0

U_27_1=0

# 1) /etc/hosts.equiv 점검
if [ -f "/etc/hosts.equiv" ]; then
    if [ "$(stat -c "%U" /etc/hosts.equiv)" != "root" ] || [ "$(stat -c "%a" /etc/hosts.equiv)" -gt 600 ] || grep -q "^\+" /etc/hosts.equiv 2>/dev/null; then
        U_27_1=1
    fi
fi

# 2) 각 사용자별 .rhosts 점검
if [ "$U_27_1" -eq 0 ]; then
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [ -d "$homedir" ] && [ -f "$homedir/.rhosts" ]; then
            f_target="$homedir/.rhosts"
            f_owner=$(stat -c "%U" "$f_target")
            f_perm=$(stat -c "%a" "$f_target")
            
            if [[ "$f_owner" != "root" && "$f_owner" != "$username" ]] || [ "$f_perm" -gt 600 ] || grep -q "^\+" "$f_target" 2>/dev/null; then
                U_27_1=1
                break
            fi
        fi
    done < /etc/passwd
fi

IS_VUL=$U_27_1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_27_1": $U_27_1 },
    "timestamp": "$DATE"
  }
}
EOF