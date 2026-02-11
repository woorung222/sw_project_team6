#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : FTP 기본 계정에 쉘 설정 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_55_1 : ftp 계정의 쉘이 /bin/false 또는 /sbin/nologin 계열인지 확인
U_55_1=0

# --- 3. 점검 로직 수행 ---

# [Step 1] ftp 계정의 로그인 쉘 확인
if grep -q "^ftp:" /etc/passwd; then
    # ftp 계정의 마지막 필드(쉘) 추출
    FTP_SHELL=$(grep "^ftp:" /etc/passwd | cut -d: -f7)

    # 판단 기준: /bin/false, /sbin/nologin, /usr/sbin/nologin 등이 아니면 취약
    if [[ "$FTP_SHELL" != "/bin/false" && "$FTP_SHELL" != "/sbin/nologin" && "$FTP_SHELL" != "/usr/sbin/nologin" ]]; then
        U_55_1=1
    fi
else
    # ftp 계정이 없으면 양호
    U_55_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_55_1" -eq 1 ]; then
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
    "flag_id": "U-55",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_55_1": $U_55_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
