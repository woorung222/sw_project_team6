#!/bin/bash

# [U-47] 스팸 메일 릴레이 제한 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : SMTP 서비스가 활성화된 경우 릴레이 제한(Relay Restriction) 설정 여부 점검
# DB 정합성 : IS_AUTO=0 (전송 장애 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_47_1=0; U_47_2=0; U_47_3=0
IS_VUL=0
IS_AUTO=0 

# 1. [U_47_1] Sendmail 점검
if systemctl is-active --quiet sendmail 2>/dev/null; then
    # 8.9 이상은 access 파일 존재 여부 및 promiscuous_relay 옵션 점검
    if [ -f "/etc/mail/sendmail.cf" ]; then
        if ! grep -v "^#" /etc/mail/sendmail.cf | grep -qi "Relaying denied"; then
            U_47_1=1
        fi
    fi
fi

# 2. [U_47_2] Postfix 점검
if systemctl is-active --quiet postfix 2>/dev/null; then
    # mynetworks 설정에서 0.0.0.0/0 (전체 릴레이) 허용 여부 점검
    RELAY_CONF=$(postconf -n mynetworks 2>/dev/null)
    if [[ "$RELAY_CONF" == *"0.0.0.0/0"* ]] || [[ "$RELAY_CONF" == *"*"* ]]; then
        U_47_2=1
    fi
fi

# 3. [U_47_3] Exim 점검
if systemctl is-active --quiet exim 2>/dev/null; then
    EXIM_CONF=$(exim -bV 2>/dev/null | grep "Configuration file" | awk '{print $3}')
    if [ -f "$EXIM_CONF" ]; then
        if grep -E "relay_from_hosts|accept hosts" "$EXIM_CONF" | grep -v "^#" | grep -q "*"; then
            U_47_3=1
        fi
    fi
fi

IS_VUL=0
[ "$U_47_1" -eq 1 ] || [ "$U_47_2" -eq 1 ] || [ "$U_47_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-47",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_47_1": $U_47_1, "U_47_2": $U_47_2, "U_47_3": $U_47_3 },
    "timestamp": "$DATE"
  }
}
EOF