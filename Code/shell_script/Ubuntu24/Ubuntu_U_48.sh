#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_48_1 : [Sendmail] PrivacyOptions 내 noexpn, novrfy 설정 여부
# U_48_2 : [Postfix] disable_vrfy_command 설정 여부
# U_48_3 : [Exim] acl_smtp_vrfy, acl_smtp_expn 제한 설정 여부
U_48_1=0
U_48_2=0
U_48_3=0

# --- 3. 점검 로직 수행 ---

# [1. Sendmail 점검]
if [ -f "/etc/mail/sendmail.cf" ]; then
    # PrivacyOptions 설정 내 novrfy, noexpn, goaway 중 하나라도 있는지 확인
    PRIV_OPT=$(grep "PrivacyOptions" /etc/mail/sendmail.cf)
    VULN_CHECK=$(echo "$PRIV_OPT" | grep -E "novrfy|noexpn|goaway")
    
    # 설정이 없으면 취약
    if [ -z "$VULN_CHECK" ]; then
        U_48_1=1
    fi
fi

# [2. Postfix 점검]
if [ -f "/etc/postfix/main.cf" ]; then
    # disable_vrfy_command = yes 설정이 되어 있는지 확인
    POSTFIX_VRFY=$(grep "disable_vrfy_command" /etc/postfix/main.cf | grep -i "yes")
    
    # 설정이 없거나 yes가 아니면 취약
    if [ -z "$POSTFIX_VRFY" ]; then
        U_48_2=1
    fi
fi

# [3. Exim 점검]
EXIM_CONF="/etc/exim/exim.conf"
[ ! -f "$EXIM_CONF" ] && EXIM_CONF="/etc/exim4/exim4.conf"

if [ -f "$EXIM_CONF" ]; then
    # acl_smtp_vrfy 또는 acl_smtp_expn 설정이 활성화(주석 아님) 되어 있으면 취약
    EXIM_CHECK=$(grep -E "acl_smtp_vrfy|acl_smtp_expn" "$EXIM_CONF" | grep -v "^#")
    
    if [ -n "$EXIM_CHECK" ]; then
        U_48_3=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_48_1" -eq 1 ] || [ "$U_48_2" -eq 1 ] || [ "$U_48_3" -eq 1 ]; then
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
    "flag_id": "U-48",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_48_1": $U_48_1,
      "U_48_2": $U_48_2,
      "U_48_3": $U_48_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
