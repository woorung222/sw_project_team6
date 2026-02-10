#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : FTP 서비스에 root 계정 접근 제한 설정 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_57_1 : [기본 FTP-ftpusers] root 계정 접근 제한 설정 여부
# U_57_2 : [vsFTP - ftpusers] root 계정 접근 제한 설정 여부
# U_57_3 : [vsFTP-user_list] root 계정 접근 제한 설정 여부
# U_57_4 : [ProFTP - ftpusers] root 계정 접근 제한 설정 여부
# U_57_5 : [ProFTP - proftpd.conf] RootLogin off 설정 여부
U_57_1=0
U_57_2=0
U_57_3=0
U_57_4=0
U_57_5=0

# --- 3. 점검 로직 수행 ---

# [1. 기본 FTP-ftpusers 점검]
FTPUSERS_FILE=""
if [ -f "/etc/ftpusers" ]; then
    FTPUSERS_FILE="/etc/ftpusers"
elif [ -f "/etc/ftpd/ftpusers" ]; then
    FTPUSERS_FILE="/etc/ftpd/ftpusers"
fi

if [ -n "$FTPUSERS_FILE" ]; then
    # 파일 내에 root 계정이 명시되어 있어야 차단됨 (grep -qx "root")
    if ! grep -qx "root" "$FTPUSERS_FILE"; then
        U_57_1=1
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
    if ! grep -qx "root" "$VS_FTPUSERS"; then
        U_57_2=1
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
    # user_list_deny=YES(기본값)인 경우 리스트에 root가 있어야 차단됨
    if ! grep -qx "root" "$VS_USERLIST"; then
        U_57_3=1
    fi
fi

# [4. ProFTP - ftpusers 점검]
if [ -f "/etc/ftpd/ftpusers" ]; then
    if ! grep -qx "root" "/etc/ftpd/ftpusers"; then
        U_57_4=1
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
    # RootLogin off 설정이 주석 없이 존재하는지 확인
    ROOT_LOGIN_OFF=$(grep -i "RootLogin" "$PROFTP_CONF" | grep -i "off" | grep -v "^#")
    if [ -z "$ROOT_LOGIN_OFF" ]; then
        U_57_5=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_57_1" -eq 1 ] || [ "$U_57_2" -eq 1 ] || [ "$U_57_3" -eq 1 ] || [ "$U_57_4" -eq 1 ] || [ "$U_57_5" -eq 1 ]; then
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
    "flag_id": "U-57",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_57_1": $U_57_1,
      "U_57_2": $U_57_2,
      "U_57_3": $U_57_3,
      "U_57_4": $U_57_4,
      "U_57_5": $U_57_5
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
