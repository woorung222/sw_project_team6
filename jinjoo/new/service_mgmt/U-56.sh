#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : FTP 서비스에 비인가자의 접근 가능 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_56_1 : [FTP - ftpusers] 파일 소유자 및 권한 설정
# U_56_2 : [vsFTP - ftpusers] 파일 소유자 및 권한 설정
# U_56_3 : [vsFTP-user_list] 파일 소유자 및 권한 설정
# U_56_4 : [ProFTP - ftpusers] 파일 소유자 및 권한 설정
# U_56_5 : [ProFTP - proftpd.conf] 파일 소유자 및 권한 설정
U_56_1=0
U_56_2=0
U_56_3=0
U_56_4=0
U_56_5=0

# --- 3. 점검 로직 수행 ---

# [1. FTP - ftpusers 점검]
if [ -f "/etc/ftpusers" ]; then
    OWNER=$(stat -c "%U" /etc/ftpusers)
    PERM=$(stat -c "%a" /etc/ftpusers)
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        U_56_1=1
    fi
fi

# [2. vsFTP - ftpusers 점검]
VS_FTPUSERS=""
if [ -f "/etc/vsftpd.ftpusers" ]; then
    VS_FTPUSERS="/etc/vsftpd.ftpusers"
elif [ -f "/etc/vsftpd/ftpusers" ]; then
    VS_FTPUSERS="/etc/vsftpd/ftpusers"
fi

if [ -n "$VS_FTPUSERS" ]; then
    OWNER=$(stat -c "%U" "$VS_FTPUSERS")
    PERM=$(stat -c "%a" "$VS_FTPUSERS")
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        U_56_2=1
    fi
fi

# [3. vsFTP-user_list 점검]
VS_USERLIST=""
if [ -f "/etc/vsftpd.user_list" ]; then
    VS_USERLIST="/etc/vsftpd.user_list"
elif [ -f "/etc/vsftpd/user_list" ]; then
    VS_USERLIST="/etc/vsftpd/user_list"
fi

if [ -n "$VS_USERLIST" ]; then
    OWNER=$(stat -c "%U" "$VS_USERLIST")
    PERM=$(stat -c "%a" "$VS_USERLIST")
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        U_56_3=1
    fi
fi

# [4. ProFTP - ftpusers 점검]
if [ -f "/etc/ftpd/ftpusers" ]; then
    OWNER=$(stat -c "%U" /etc/ftpd/ftpusers)
    PERM=$(stat -c "%a" /etc/ftpd/ftpusers)
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        U_56_4=1
    fi
fi

# [5. ProFTP - proftpd.conf 점검]
PROFTP_CONF=""
if [ -f "/etc/proftpd/proftpd.conf" ]; then
    PROFTP_CONF="/etc/proftpd/proftpd.conf"
elif [ -f "/etc/proftpd.conf" ]; then
    PROFTP_CONF="/etc/proftpd.conf"
fi

if [ -n "$PROFTP_CONF" ]; then
    OWNER=$(stat -c "%U" "$PROFTP_CONF")
    PERM=$(stat -c "%a" "$PROFTP_CONF")
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 640 ]; then
        U_56_5=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_56_1" -eq 1 ] || [ "$U_56_2" -eq 1 ] || [ "$U_56_3" -eq 1 ] || [ "$U_56_4" -eq 1 ] || [ "$U_56_5" -eq 1 ]; then
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
    "flag_id": "U-56",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_56_1": $U_56_1,
      "U_56_2": $U_56_2,
      "U_56_3": $U_56_3,
      "U_56_4": $U_56_4,
      "U_56_5": $U_56_5
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
