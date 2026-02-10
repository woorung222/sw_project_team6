#!/bin/bash

# [U-20] /etc/(x)inetd.conf 파일 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 설정 파일의 소유자가 root이고, 권한이 600 이하인 경우 양호
# 주의 : Systemd 설정 파일의 경우 가이드 기준(600)이 실제 운영 환경(644)보다 엄격할 수 있음

# 1. 메타 데이터 수집
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
    # 소유자 root 아님 OR 권한이 600 초과 (Group이나 Other에 권한이 있음)
    if [ "$(stat -c %U "$INETD_CONF")" != "root" ] || [ "$(stat -c %a "$INETD_CONF")" -gt 600 ]; then
        U_20_1=1
    fi
else
    # 파일이 없으면 양호
    U_20_1=0
fi

# --- [U_20_2] Xinetd 점검 ---
XINETD_CONF="/etc/xinetd.conf"
XINETD_DIR="/etc/xinetd.d"
VULN_XINETD=0

# 1. 메인 설정 파일 점검
if [ -f "$XINETD_CONF" ]; then
    if [ "$(stat -c %U "$XINETD_CONF")" != "root" ] || [ "$(stat -c %a "$XINETD_CONF")" -gt 600 ]; then
        VULN_XINETD=1
    fi
fi

# 2. 디렉터리 내 파일 점검
if [ -d "$XINETD_DIR" ]; then
    # 소유자가 root가 아니거나, 권한이 600보다 큰 파일(Group/Other에 권한 존재) 검색
    # -perm /g+rwx,o+rwx : 그룹이나 Other에 r,w,x 중 하나라도 있으면 탐지
    FOUND_BAD=$(find "$XINETD_DIR" -type f \( ! -user root -o -perm /g+rwx,o+rwx \) -print -quit 2>/dev/null)
    if [ ! -z "$FOUND_BAD" ]; then
        VULN_XINETD=1
    fi
fi

if [ $VULN_XINETD -eq 1 ]; then
    U_20_2=1
else
    U_20_2=0
fi

# --- [U_20_3] Systemd 점검 ---
SYSTEMD_CONF="/etc/systemd/system.conf"
SYSTEMD_DIR="/etc/systemd"
VULN_SYSTEMD=0

# 1. system.conf 점검
if [ -f "$SYSTEMD_CONF" ]; then
    # 권한이 600 보다 큰지 확인 (즉, 644 등은 취약으로 간주)
    PERM=$(stat -c %a "$SYSTEMD_CONF")
    OWNER=$(stat -c %U "$SYSTEMD_CONF")
    
    # 600은 rw------- 이므로, 600보다 크거나 같은 권한 중 Group/Other 권한이 있으면 취약
    # 간단히 600 초과 여부로 판단 (단, 700 같은 경우는 예외이나 설정파일은 실행권한 없으므로 보통 숫자 비교 가능)
    # 정확히는: Group이나 Other에 r,w,x 비트가 하나라도 있으면 취약
    if [ "$OWNER" != "root" ] || [ "$(stat -c %a "$SYSTEMD_CONF" | awk '{if($1>600) print 1; else print 0}')" -eq 1 ]; then
        VULN_SYSTEMD=1
    fi
fi

# 2. /etc/systemd/ 디렉터리 내 파일 점검
if [ -d "$SYSTEMD_DIR" ]; then
    # 가이드 기준: 모든 파일의 권한 600
    # find 조건: 파일타입(-f), (소유자!=root OR 권한에 Group/Other 비트 설정됨)
    FOUND_BAD_SYS=$(find "$SYSTEMD_DIR" -type f \( ! -user root -o -perm /g+rwx,o+rwx \) -print -quit 2>/dev/null)
    
    if [ ! -z "$FOUND_BAD_SYS" ]; then
        VULN_SYSTEMD=1
    fi
fi

if [ $VULN_SYSTEMD -eq 1 ]; then
    U_20_3=1
else
    U_20_3=0
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