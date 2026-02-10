#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : FTP 서비스 접속 배너를 통한 불필요한 정보 노출 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_53_1 : [vsFTP] ftpd_banner 설정 및 정보 노출 여부
# U_53_2 : [ProFTP] ServerIdent 설정 및 정보 노출 여부
U_53_1=0
U_53_2=0

# --- 3. 점검 로직 수행 ---

# [1. vsFTP 점검]
VSFTP_CONF=""
if [ -f "/etc/vsftpd.conf" ]; then
    VSFTP_CONF="/etc/vsftpd.conf"
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    VSFTP_CONF="/etc/vsftpd/vsftpd.conf"
fi

if [ -n "$VSFTP_CONF" ]; then
    # ftpd_banner 설정이 주석 처리되지 않고 존재하는지 확인
    BANNER_CHECK=$(grep -i "ftpd_banner" "$VSFTP_CONF" | grep -v "^#")
    
    if [ -z "$BANNER_CHECK" ]; then
        U_53_1=1
    fi
fi

# [2. ProFTP 점검]
PROFTP_CONF=""
if [ -f "/etc/proftpd.conf" ]; then
    PROFTP_CONF="/etc/proftpd.conf"
elif [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTP_CONF="/etc/proftpd/proftpd.conf"
fi

if [ -n "$PROFTP_CONF" ]; then
    # ServerIdent 설정 확인
    IDENT_CHECK=$(grep -i "ServerIdent" "$PROFTP_CONF" | grep -v "^#")
    
    # 1. 설정이 아예 없으면 취약 (기본값 노출)
    if [ -z "$IDENT_CHECK" ]; then
        U_53_2=1
    else
        # 2. 설정은 있으나 'on'이면서 사용자 지정 메시지(따옴표)가 없는 경우 취약
        if echo "$IDENT_CHECK" | grep -iq "on" && ! echo "$IDENT_CHECK" | grep -q "\""; then
            U_53_2=1
        fi
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_53_1" -eq 1 ] || [ "$U_53_2" -eq 1 ]; then
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
    "flag_id": "U-53",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_53_1": $U_53_1,
      "U_53_2": $U_53_2
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
