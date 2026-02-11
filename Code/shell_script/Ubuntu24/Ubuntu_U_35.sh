#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 주요 파일 전송 서비스(FTP, vsFTP, ProFTP, NFS, Samba)의 익명 접속 및 취약 설정 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_35_1 : 기본 FTP (inetd/xinetd) 활성화 여부
# U_35_2 : vsFTPd 익명 접속 허용 여부
# U_35_3 : ProFTPd 익명 접속 허용 여부
# U_35_4 : NFS 취약 옵션 설정 여부
# U_35_5 : Samba Guest 접속 허용 여부
U_35_1=0
U_35_2=0
U_35_3=0
U_35_4=0
U_35_5=0

# --- 3. 점검 로직 수행 ---

# [U_35_1] 기본 FTP 서비스 점검 (inetd/xinetd)
if sudo grep -rE "ftp" /etc/inetd.conf /etc/xinetd.d/* 2>/dev/null | grep -v "^#" > /dev/null; then
    U_35_1=1
fi

# [U_35_2] vsFTPd 익명 접속 점검
if [ -f "/etc/vsftpd.conf" ]; then
    if sudo grep -i "anonymous_enable=YES" /etc/vsftpd.conf | grep -v "^#" > /dev/null; then
        U_35_2=1
    fi
elif [ -f "/etc/vsftpd/vsftpd.conf" ]; then
    # Ubuntu의 경우 경로가 다를 수 있어 추가 확인
    if sudo grep -i "anonymous_enable=YES" /etc/vsftpd/vsftpd.conf | grep -v "^#" > /dev/null; then
        U_35_2=1
    fi
fi

# [U_35_3] ProFTPd 익명 접속 점검
if [ -f "/etc/proftpd/proftpd.conf" ]; then
    if sudo grep -i "<Anonymous" /etc/proftpd/proftpd.conf | grep -v "^#" > /dev/null; then
        U_35_3=1
    fi
fi

# [U_35_4] NFS 공유 설정 점검
if [ -f "/etc/exports" ]; then
    # insecure, all_squash, no_root_squash, anonuid, anongid 등 취약 옵션 확인
    if sudo grep -E "(insecure|all_squash|no_root_squash|anonuid|anongid)" /etc/exports | grep -v "^#" > /dev/null; then
        U_35_4=1
    fi
fi

# [U_35_5] Samba Guest 접속 점검
if [ -f "/etc/samba/smb.conf" ]; then
    if sudo grep -Ei "(guest ok = yes|map to guest = bad user|public = yes)" /etc/samba/smb.conf | grep -v "^#" > /dev/null; then
        U_35_5=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_35_1" -eq 1 ] || [ "$U_35_2" -eq 1 ] || [ "$U_35_3" -eq 1 ] || [ "$U_35_4" -eq 1 ] || [ "$U_35_5" -eq 1 ]; then
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
    "flag_id": "U-35",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_35_1": $U_35_1,
      "U_35_2": $U_35_2,
      "U_35_3": $U_35_3,
      "U_35_4": $U_35_4,
      "U_35_5": $U_35_5
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
