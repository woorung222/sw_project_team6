#!/bin/bash

# [U-53] FTP 서비스 정보 노출 제한 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : vsftpd, proftpd 서비스 이용 시 배너 정보 노출 제한 설정 여부 점검
# DB 정합성 : IS_AUTO=1 (자동화 스크립트 적용 가능)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_53_1=0; U_53_2=0
IS_VUL=0
IS_AUTO=1 

# 1. [U_53_1] vsFTP 점검
if rpm -q vsftpd >/dev/null 2>&1; then
    VS_CONF="/etc/vsftpd/vsftpd.conf"
    [ ! -f "$VS_CONF" ] && VS_CONF="/etc/vsftpd.conf"
    
    if [ -f "$VS_CONF" ]; then
        # ftpd_banner 설정이 있는지 확인 (주석 제외)
        if ! grep -v "^#" "$VS_CONF" | grep -qi "ftpd_banner"; then
            U_53_1=1
        fi
    else
        U_53_1=1 # 패키지는 있는데 설정 파일이 없으면 기본 배너 노출 가능성 높음
    fi
fi

# 2. [U_53_2] ProFTP 점검
if rpm -q proftpd >/dev/null 2>&1; then
    PRO_CONF="/etc/proftpd.conf"
    [ ! -f "$PRO_CONF" ] && PRO_CONF="/etc/proftpd/proftpd.conf"

    if [ -f "$PRO_CONF" ]; then
        # ServerIdent 설정이 있고, "off" 또는 특정 메시지로 제한되어 있는지 확인
        IDENT=$(grep -v "^#" "$PRO_CONF" | grep -i "ServerIdent")
        if [ -z "$IDENT" ] || echo "$IDENT" | grep -qi "on"; then
            U_53_2=1
        fi
    else
        U_53_2=1
    fi
fi

[ "$U_53_1" -eq 1 ] || [ "$U_53_2" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-53",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_53_1": $U_53_1, "U_53_2": $U_53_2 },
    "timestamp": "$DATE"
  }
}
EOF