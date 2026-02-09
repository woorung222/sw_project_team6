#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 암호화되지 않은 FTP 서비스 비활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_54_1 : [inetd] FTP 서비스 활성화 여부
# U_54_2 : [xinetd] FTP 서비스 활성화 여부
# U_54_3 : [vsFTP] FTP 서비스 활성화 여부
# U_54_4 : [ProFTP] FTP 서비스 활성화 여부
U_54_1=0
U_54_2=0
U_54_3=0
U_54_4=0

# --- 3. 점검 로직 수행 ---

# [1. inetd 점검]
if [ -f "/etc/inetd.conf" ]; then
    # 주석(#)이 아닌 라인에서 ftp 검색
    if grep -i "ftp" /etc/inetd.conf | grep -v "^#" > /dev/null; then
        U_54_1=1
    fi
fi

# [2. xinetd 점검]
if [ -f "/etc/xinetd.d/ftp" ]; then
    # disable = no 설정 확인
    if grep -i "disable" /etc/xinetd.d/ftp | grep -i "no" > /dev/null; then
        U_54_2=1
    fi
fi

# [3. vsFTP 점검]
# systemctl list-units 명령으로 vsftpd 서비스 확인
if systemctl list-units --type=service 2>/dev/null | grep -q "vsftpd"; then
    U_54_3=1
fi

# [4. ProFTP 점검]
# systemctl list-units 명령으로 proftp 서비스 확인
if systemctl list-units --type=service 2>/dev/null | grep -q "proftp"; then
    U_54_4=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_54_1" -eq 1 ] || [ "$U_54_2" -eq 1 ] || [ "$U_54_3" -eq 1 ] || [ "$U_54_4" -eq 1 ]; then
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
    "flag_id": "U-54",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_54_1": $U_54_1,
      "U_54_2": $U_54_2,
      "U_54_3": $U_54_3,
      "U_54_4": $U_54_4
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
