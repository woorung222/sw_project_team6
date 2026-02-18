#!/bin/bash

# [U-01] root 계정의 원격터미널 접속 차단 설정
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_01_1=0 # Telnet (0: 양호, 1: 취약)
U_01_2=0 # SSH (0: 양호, 1: 취약)
IS_VUL=0 # 전체 취약 여부

# --- [Telnet] 진단 (U_01_1) ---
# Rocky 9에서는 기본적으로 Telnet이 설치/활성화되지 않음.
# 서비스가 없거나 비활성화 상태면 양호로 판단.

# Telnet 서비스 활성화 여부 확인 (systemd 및 xinetd 확인)
TELNET_ACTIVE=0
if systemctl is-active --quiet telnet.socket 2>/dev/null || \
   systemctl is-active --quiet telnet.service 2>/dev/null; then
    TELNET_ACTIVE=1
fi

# Telnet이 활성화된 경우 설정 파일 점검
if [ $TELNET_ACTIVE -eq 1 ]; then
    # 1. /etc/pam.d/login 파일 내 pam_securetty.so 설정 확인
    PAM_CHECK=$(grep -v "^#" /etc/pam.d/login | grep "pam_securetty.so")
    
    # 2. /etc/securetty 파일 내 pts/x 설정 확인 (파일이 없으면 안전, 있으면 pts 확인)
    PTS_CHECK=""
    if [ -f "/etc/securetty" ]; then
        PTS_CHECK=$(grep -v "^#" /etc/securetty | grep "^pts/")
    fi

    # 판단: PAM 모듈이 없거나, securetty에 pts가 존재하면 취약
    if [ -z "$PAM_CHECK" ] || [ ! -z "$PTS_CHECK" ]; then
        U_01_1=1
    else
        U_01_1=0
    fi
else
    # Telnet 서비스를 사용하지 않으므로 양호
    U_01_1=0
fi

# --- [SSH] 진단 (U_01_2) ---
# /etc/ssh/sshd_config 파일 점검
SSHD_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSHD_CONFIG" ]; then
    # 주석 제외, 대소문자 무시하고 PermitRootLogin 설정 확인
    # awk를 사용하여 값만 추출 (예: PermitRootLogin no -> no)
    PERMIT_ROOT=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" | grep -v "^#" | awk '{print $2}')

    # 값이 no(또는 No, NO)가 아니면 취약
    if [[ "$PERMIT_ROOT" =~ ^[Nn][Oo]$ ]]; then
        U_01_2=0
    else
        U_01_2=1
    fi
else
    # 설정 파일이 없으면 보안상 취약으로 간주 (혹은 점검 불가)
    U_01_2=1
fi

# --- 전체 결과 집계 ---
if [ $U_01_1 -eq 1 ] || [ $U_01_2 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-01",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_01_1": $U_01_1,
      "U_01_2": $U_01_2
    },
    "timestamp": "$DATE"
  }
}
EOF