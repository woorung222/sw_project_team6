#!/usr/bin/env bash
set -u

# =========================================================
# U_46 (상) 일반 사용자의 메일 서비스 실행 방지 | Ubuntu 24.04
# - 진단 기준 : SMTP 서비스 관리 명령어 권한 및 옵션 제한 점검
# - DB 정합성 : IS_AUTO=0
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_46"
CATEGORY="service"
IS_AUTO=0

U_46_1=0; U_46_2=0; U_46_3=0

# 1) Sendmail 점검
if [ -f "/etc/mail/sendmail.cf" ]; then
    if ! grep -v "^#" /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep -q "restrictqrun"; then
        U_46_1=1
    fi
fi

# 2) Postfix 점검
POSTSUPER=$(command -v postsuper)
if [ -n "$POSTSUPER" ]; then
    # Other 실행 권한 확인 (8진수 마지막 자리가 홀수인지 체크)
    if [ $(( $(stat -c "%a" "$POSTSUPER") % 2 )) -eq 1 ]; then
        U_46_2=1
    fi
fi

# 3) Exim 점검
EXIQGREP=$(command -v exiqgrep)
if [ -n "$EXIQGREP" ]; then
    if [ $(( $(stat -c "%a" "$EXIQGREP") % 2 )) -eq 1 ]; then
        U_46_3=1
    fi
fi

IS_VUL=0
[ "$U_46_1" -eq 1 ] || [ "$U_46_2" -eq 1 ] || [ "$U_46_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOST", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": { "U_46_1": $U_46_1, "U_46_2": $U_46_2, "U_46_3": $U_46_3 },
    "timestamp": "$DATE"
  }
}
EOF