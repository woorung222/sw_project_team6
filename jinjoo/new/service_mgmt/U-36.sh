#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : r-services(rlogin, rsh, rexec) 관련 패키지 및 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_36_1 : [/etc/inetd.conf] 설정 점검
# U_36_2 : [/etc/xinetd.d/] 설정 점검
# U_36_3 : [systemd] 서비스 유닛 점검
# U_36_4 : [Package] r-services 관련 패키지 설치 여부
U_36_1=0
U_36_2=0
U_36_3=0
U_36_4=0

# --- 3. 점검 로직 수행 ---

# [U_36_1] /etc/inetd.conf 점검
if [ -f "/etc/inetd.conf" ]; then
    # login, shell, exec 서비스가 주석 처리되지 않고 활성화되어 있는지 확인
    if sudo grep -E "^\s*(login|shell|exec)\s+" /etc/inetd.conf | grep -v "^#" > /dev/null; then
        echo "  - [취약] inetd.conf 내 r-service 활성화됨" >&2
        U_36_1=1
    fi
fi

# [U_36_2] /etc/xinetd.d/ 점검
if [ -d "/etc/xinetd.d" ]; then
    # disable = no 로 설정된 항목 중 rlogin, rsh, rexec가 포함된 경우 확인
    X_CHECK=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -E "(rlogin|rsh|rexec)")
    if [ -n "$X_CHECK" ]; then
        echo "  - [취약] xinetd 내 r-service 활성화됨" >&2
        U_36_2=1
    fi
fi

# [U_36_3] systemd 서비스 점검
# 관련 유닛 파일들이 enabled 상태인지 확인
R_UNITS=$(systemctl list-unit-files 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell.target|login.target|exec.target)" | grep "enabled")
if [ -n "$R_UNITS" ]; then
    echo "  - [취약] systemd 유닛 활성화됨 ($R_UNITS)" >&2
    U_36_3=1
fi

# [U_36_4] 패키지 설치 여부 점검
# rsh-server, rsh-client, rlogin, rexec 등 관련 패키지 설치(ii) 상태 확인
R_PKGS=$(dpkg -l | grep -E "rsh-server|rsh-redone-server|rsh-client|rlogin|rexec" | grep "^ii" | awk '{print $2}')
if [ -n "$R_PKGS" ]; then
    echo "  - [취약] r-service 관련 패키지 설치됨 ($R_PKGS)" >&2
    U_36_4=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_36_1" -eq 1 ] || [ "$U_36_2" -eq 1 ] || [ "$U_36_3" -eq 1 ] || [ "$U_36_4" -eq 1 ]; then
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
    "flag_id": "U-36",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_36_1": $U_36_1,
      "U_36_2": $U_36_2,
      "U_36_3": $U_36_3,
      "U_36_4": $U_36_4
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
