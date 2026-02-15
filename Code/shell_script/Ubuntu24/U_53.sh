#!/usr/bin/env bash
set -u

# =========================================================
# U_53 (하) FTP 서비스 정보 노출 제한 | Ubuntu 24.04
# - 진단 기준 : FTP 배너 메시지(Banner) 정보 노출 제한 설정 여부
# - DB 정합성 : IS_AUTO=1
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_53"
CATEGORY="service"
IS_AUTO=1

U_53_1=0; U_53_2=0

# 1) vsFTP 점검
VS_CONF="/etc/vsftpd.conf"
[ ! -f "$VS_CONF" ] && VS_CONF="/etc/vsftpd/vsftpd.conf"
if [ -f "$VS_CONF" ]; then
    if ! grep -v "^#" "$VS_CONF" | grep -qi "ftpd_banner"; then
        U_53_1=1
    fi
fi

# 2) ProFTP 점검
PRO_CONF="/etc/proftpd/proftpd.conf"
[ ! -f "$PRO_CONF" ] && PRO_CONF="/etc/proftpd.conf"
if [ -f "$PRO_CONF" ]; then
    IDENT_CHECK=$(grep -v "^#" "$PRO_CONF" | grep -i "ServerIdent")
    # 설정이 없거나 'on'으로 되어 있으면 버전이 노출됨
    if [ -z "$IDENT_CHECK" ] || echo "$IDENT_CHECK" | grep -qi "on"; then
        U_53_2=1
    fi
fi

IS_VUL=0
[ "$U_53_1" -eq 1 ] || [ "$U_53_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_53_1": $U_53_1, "U_53_2": $U_53_2 },
    "timestamp": "$DATE"
  }
}
EOF