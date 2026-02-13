#!/usr/bin/env bash
set -u

# =========================================================
# U_48 (중) expn, vrfy 명령어 제한 | Ubuntu 24.04
# - 진단 기준 : SMTP 서비스 정보 수집 명령어(vrfy, expn) 제한 여부 점검
# - DB 정합성 : IS_AUTO=0
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_48"
CATEGORY="service"
IS_AUTO=0

U_48_1=0; U_48_2=0; U_48_3=0

# 1) Sendmail 점검
if [ -f "/etc/mail/sendmail.cf" ]; then
    PRIV_OPT=$(grep -v "^#" /etc/mail/sendmail.cf | grep "PrivacyOptions")
    # novrfy, noexpn 또는 이들을 포함하는 goaway 옵션 체크
    if ! echo "$PRIV_OPT" | grep -qE "novrfy|goaway" || ! echo "$PRIV_OPT" | grep -qE "noexpn|goaway"; then
        U_48_1=1
    fi
fi

# 2) Postfix 점검
if command -v postconf >/dev/null; then
    if [ "$(postconf -h disable_vrfy_command 2>/dev/null)" != "yes" ]; then
        U_48_2=1
    fi
fi

# 3) Exim 점검
E_CONF="/etc/exim4/exim4.conf"
[ ! -f "$E_CONF" ] && E_CONF="/etc/exim/exim.conf"
if [ -f "$E_CONF" ]; then
    if grep -E "acl_smtp_vrfy|acl_smtp_expn" "$E_CONF" | grep -v "^#" | grep -q "accept"; then
        U_48_3=1
    fi
fi

IS_VUL=0
[ "$U_48_1" -eq 1 ] || [ "$U_48_2" -eq 1 ] || [ "$U_48_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_48_1": $U_48_1, "U_48_2": $U_48_2, "U_48_3": $U_48_3 },
    "timestamp": "$DATE"
  }
}
EOF