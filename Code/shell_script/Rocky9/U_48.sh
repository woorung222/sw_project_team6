#!/bin/bash

# [U-48] expn, vrfy 명령어 제한 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : SMTP 서비스에서 expn, vrfy 명령어가 차단되어 있는 경우 양호
# DB 정합성 : IS_AUTO=0 (메일 설정 변경 및 서비스 재시작 위험으로 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_48_1=0; U_48_2=0; U_48_3=0
IS_VUL=0
IS_AUTO=0 

# 1. [U_48_1] Sendmail 점검
if systemctl is-active --quiet sendmail 2>/dev/null; then
    CF_FILE="/etc/mail/sendmail.cf"
    if [ -f "$CF_FILE" ]; then
        # PrivacyOptions에 novrfy와 noexpn(또는 goaway)이 포함되어 있는지 확인
        PRIV_OPT=$(grep -v "^#" "$CF_FILE" | grep "PrivacyOptions")
        if ! echo "$PRIV_OPT" | grep -qE "novrfy|goaway" || ! echo "$PRIV_OPT" | grep -qE "noexpn|goaway"; then
            U_48_1=1
        fi
    else
        U_48_1=1 # 서비스 활성 중인데 설정 파일이 없으면 취약
    fi
fi

# 2. [U_48_2] Postfix 점검
if systemctl is-active --quiet postfix 2>/dev/null; then
    # disable_vrfy_command 값이 yes인지 확인
    if [ "$(postconf -h disable_vrfy_command 2>/dev/null)" != "yes" ]; then
        U_48_2=1
    fi
fi

# 3. [U_48_3] Exim 점검
if systemctl is-active --quiet exim 2>/dev/null; then
    EXIM_CONF=$(exim -bV 2>/dev/null | grep "Configuration file" | awk '{print $3}')
    if [ -f "$EXIM_CONF" ]; then
        # vrfy 또는 expn에 대해 accept(허용) 설정이 있는지 확인
        if grep -E "acl_smtp_vrfy|acl_smtp_expn" "$EXIM_CONF" | grep -v "^#" | grep -q "accept"; then
            U_48_3=1
        fi
    fi
fi

# 최종 결과 집계
[ "$U_48_1" -eq 1 ] || [ "$U_48_2" -eq 1 ] || [ "$U_48_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-48",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_48_1": $U_48_1, "U_48_2": $U_48_2, "U_48_3": $U_48_3 },
    "timestamp": "$DATE"
  }
}
EOF