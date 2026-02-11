#!/bin/bash

# [U-20] /etc/(x)inetd.conf 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 설정 파일의 소유자가 root이고, 권한이 600 이하인 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-20"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

# 2. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_20_1=0 # inetd
U_20_2=0 # xinetd
U_20_3=0 # systemd
IS_VUL=0

# --- [U_20_1] Inetd 점검 ---
INETD_CONF="/etc/inetd.conf"
if [ -f "$INETD_CONF" ]; then
    OWNER=$(run_cmd "[U_20_1] inetd.conf 소유자 확인" "stat -c %U $INETD_CONF")
    PERM=$(run_cmd "[U_20_1] inetd.conf 권한 확인" "stat -c %a $INETD_CONF")
    
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        U_20_1=1
        log_basis "[U_20_1] inetd.conf 권한($PERM) 또는 소유자($OWNER) 취약" "취약"
    else
        U_20_1=0
        log_basis "[U_20_1] inetd.conf 설정 양호" "양호"
    fi
else
    U_20_1=0
    log_basis "[U_20_1] inetd.conf 파일 없음 (미사용)" "양호"
fi

# --- [U_20_2] Xinetd 점검 ---
XINETD_CONF="/etc/xinetd.conf"
XINETD_DIR="/etc/xinetd.d"
VULN_XINETD=0

# 1. 메인 설정 파일 점검
if [ -f "$XINETD_CONF" ]; then
    OWNER=$(run_cmd "[U_20_2] xinetd.conf 소유자 확인" "stat -c %U $XINETD_CONF")
    PERM=$(run_cmd "[U_20_2] xinetd.conf 권한 확인" "stat -c %a $XINETD_CONF")

    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        VULN_XINETD=1
    fi
fi

# 2. 디렉터리 내 파일 점검
if [ -d "$XINETD_DIR" ]; then
    CMD_FIND="find $XINETD_DIR -type f \( ! -user root -o -perm /g+rwx,o+rwx \) -print -quit 2>/dev/null"
    FOUND_BAD=$(run_cmd "[U_20_2] xinetd.d 내 취약 파일 검색" "$CMD_FIND")
    if [ -n "$FOUND_BAD" ]; then
        VULN_XINETD=1
    fi
fi

if [ $VULN_XINETD -eq 1 ]; then
    U_20_2=1
    log_basis "[U_20_2] xinetd 설정 파일 권한 또는 소유자 취약" "취약"
else
    U_20_2=0
    log_basis "[U_20_2] xinetd 설정 파일 양호" "양호"
fi

# --- [U_20_3] Systemd 점검 ---
SYSTEMD_CONF="/etc/systemd/system.conf"
SYSTEMD_DIR="/etc/systemd"
VULN_SYSTEMD=0

# 1. system.conf 점검
if [ -f "$SYSTEMD_CONF" ]; then
    OWNER=$(run_cmd "[U_20_3] system.conf 소유자 확인" "stat -c %U $SYSTEMD_CONF")
    PERM=$(run_cmd "[U_20_3] system.conf 권한 확인" "stat -c %a $SYSTEMD_CONF")
    
    # awk 로직 run_cmd로 처리하기 복잡하므로 간단히 쉘 변수 비교로 대체 (로직 유지)
    if [ "$OWNER" != "root" ] || [ "$PERM" -gt 600 ]; then
        VULN_SYSTEMD=1
    fi
fi

# 2. /etc/systemd/ 디렉터리 내 파일 점검
if [ -d "$SYSTEMD_DIR" ]; then
    CMD_FIND_SYS="find $SYSTEMD_DIR -type f \( ! -user root -o -perm /g+rwx,o+rwx \) -print -quit 2>/dev/null"
    FOUND_BAD_SYS=$(run_cmd "[U_20_3] /etc/systemd 내 취약 파일 검색" "$CMD_FIND_SYS")
    
    if [ -n "$FOUND_BAD_SYS" ]; then
        VULN_SYSTEMD=1
    fi
fi

if [ $VULN_SYSTEMD -eq 1 ]; then
    U_20_3=1
    log_basis "[U_20_3] systemd 설정 파일 권한 또는 소유자 취약" "취약"
else
    U_20_3=0
    log_basis "[U_20_3] systemd 설정 파일 양호" "양호"
fi


# --- 전체 결과 집계 ---
if [ $U_20_1 -eq 1 ] || [ $U_20_2 -eq 1 ] || [ $U_20_3 -eq 1 ]; then
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
    "flag_id": "U-20",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_20_1": $U_20_1,
      "U_20_2": $U_20_2,
      "U_20_3": $U_20_3
    },
    "timestamp": "$DATE"
  }
}
EOF
