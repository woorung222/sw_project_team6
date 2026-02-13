#!/bin/bash

# [U-20] /etc/(x)inetd.conf 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 설정 파일의 소유자가 root이고, 권한이 600 이하인 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 1)
U_20_1=0 # inetd
U_20_2=0 # xinetd
U_20_3=0 # systemd
IS_VUL=0
IS_AUTO=1 

# --- [U_20_1] Inetd 점검 ---
INETD_CONF="/etc/inetd.conf"
if [ -f "$INETD_CONF" ]; then
    if [ "$(stat -c %U "$INETD_CONF")" != "root" ] || [ "$(stat -c %a "$INETD_CONF")" -gt 600 ]; then
        U_20_1=1
    fi
fi

# --- [U_20_2] Xinetd 점검 ---
XINETD_CONF="/etc/xinetd.conf"
XINETD_DIR="/etc/xinetd.d"
# 메인 설정 파일 점검
if [ -f "$XINETD_CONF" ]; then
    if [ "$(stat -c %U "$XINETD_CONF")" != "root" ] || [ "$(stat -c %a "$XINETD_CONF")" -gt 600 ]; then
        U_20_2=1
    fi
fi
# 하위 디렉터리 파일 점검
if [ -d "$XINETD_DIR" ]; then
    if find "$XINETD_DIR" -type f \( ! -user root -o -perm /077 \) -print -quit 2>/dev/null | grep -q .; then
        U_20_2=1
    fi
fi

# --- [U_20_3] Systemd 설정 점검 ---
SYSTEMD_CONF="/etc/systemd/system.conf"
SYSTEMD_DIR="/etc/systemd"
if [ -f "$SYSTEMD_CONF" ]; then
    if [ "$(stat -c %U "$SYSTEMD_CONF")" != "root" ] || [ "$(stat -c %a "$SYSTEMD_CONF")" -gt 600 ]; then
        U_20_3=1
    fi
fi
if [ -d "$SYSTEMD_DIR" ]; then
    if find "$SYSTEMD_DIR" -type f \( ! -user root -o -perm /077 \) -print -quit 2>/dev/null | grep -q .; then
        U_20_3=1
    fi
fi

# 최종 결과 집계
[ "$U_20_1" -eq 1 ] || [ "$U_20_2" -eq 1 ] || [ "$U_20_3" -eq 1 ] && IS_VUL=1

# JSON 출력
cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-20",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "file",
    "flag": { "U_20_1": $U_20_1, "U_20_2": $U_20_2, "U_20_3": $U_20_3 },
    "timestamp": "$DATE"
  }
}
EOF