#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : SMTP 서버의 릴레이 기능 제한 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_47_1 : [Sendmail] 버전별 릴레이 제한 설정 여부
# U_47_2 : [Postfix] 릴레이 정책 설정 여부
# U_47_3 : [Exim] 릴레이 허용 네트워크 설정 여부
U_47_1=0
U_47_2=0
U_47_3=0

# --- 3. 점검 로직 수행 ---

# [1. Sendmail 점검]
if command -v sendmail > /dev/null; then
    # 버전 정보 추출
    SENDMAIL_VER_FULL=$(sendmail -d0.1 -bt < /dev/null 2>&1 | grep "Version" | awk '{print $2}')
    # 메이저.마이너 버전 추출 (예: 8.15)
    SENDMAIL_VER_MAJOR=$(echo "$SENDMAIL_VER_FULL" | cut -d. -f1,2)
    
    # 버전 비교 (bc 사용)
    IS_LEGACY=0
    if command -v bc > /dev/null; then
        IS_LEGACY=$(echo "$SENDMAIL_VER_MAJOR < 8.9" | bc -l 2>/dev/null)
    fi

    if [ "$IS_LEGACY" == "1" ]; then
        # [Sendmail 8.9 미만] Relaying denied 설정 확인
        # sendmail.cf 파일 내 "Relaying denied" 룰이 있는지 확인
        RELAY_DENY_CHECK=$(grep "R$\*" /etc/mail/sendmail.cf 2>/dev/null | grep "Relaying denied")
        if [ -z "$RELAY_DENY_CHECK" ]; then
            U_47_1=1
        fi
    else
        # [Sendmail 8.9 이상] promiscuous_relay 설정 확인 (활성화 시 취약)
        if [ -f "/etc/mail/sendmail.mc" ]; then
            RELAY_FEATURE=$(grep "FEATURE.*promiscuous_relay" /etc/mail/sendmail.mc)
            if [ -n "$RELAY_FEATURE" ]; then
                U_47_1=1
            fi
        fi
    fi
fi

# [2. Postfix 점검]
if [ -f "/etc/postfix/main.cf" ]; then
    # smtpd_recipient_restrictions 또는 mynetworks 설정 확인
    POSTFIX_RELAY=$(grep -E "smtpd_recipient_restrictions|mynetworks" /etc/postfix/main.cf)
    if [ -z "$POSTFIX_RELAY" ]; then
        U_47_2=1
    fi
fi

# [3. Exim 점검]
EXIM_CONF="/etc/exim/exim.conf"
[ ! -f "$EXIM_CONF" ] && EXIM_CONF="/etc/exim4/exim4.conf"

if [ -f "$EXIM_CONF" ]; then
    # relay_from_hosts 또는 hosts= 설정 확인
    EXIM_RELAY=$(grep -E "relay_from_hosts|hosts=" "$EXIM_CONF")
    if [ -z "$EXIM_RELAY" ]; then
        U_47_3=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_47_1" -eq 1 ] || [ "$U_47_2" -eq 1 ] || [ "$U_47_3" -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-47",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_47_1": $U_47_1,
      "U_47_2": $U_47_2,
      "U_47_3": $U_47_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
