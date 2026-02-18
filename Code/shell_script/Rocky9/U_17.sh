#!/bin/bash

# [U-17] 시스템 시작 스크립트 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 
#   U_17_1 : /etc/rc.d 내 파일 소유자가 root이고, other 쓰기 권한이 없는 경우
#   U_17_2 : /etc/systemd/system 내 파일 소유자가 root이고, other 쓰기 권한이 없는 경우

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (0: 양호, 1: 취약)
U_17_1=0 
U_17_2=0
IS_VUL=0

# --- [U_17_1] Init 스크립트 점검 (/etc/rc.d) ---
# Rocky 9에서도 /etc/rc.d/init.d 등이 존재할 수 있음
INIT_DIR="/etc/rc.d"

if [ -d "$INIT_DIR" ]; then
    # find -L: 심볼릭 링크를 따라가서 원본 파일 점검
    # ! -user root: 소유자가 root가 아닌 것
    # -o: OR
    # -perm -o+w: other에게 쓰기 권한이 있는 것
    # -print -quit: 하나라도 발견되면 즉시 종료 (속도 최적화)
    
    VULN_INIT=$(find -L "$INIT_DIR" -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null)
    
    if [ -z "$VULN_INIT" ]; then
        U_17_1=0
    else
        # 취약 파일 발견
        U_17_1=1
    fi
else
    # 디렉터리가 없으면 해당 사항 없음(양호)
    U_17_1=0
fi

# --- [U_17_2] Systemd 유닛 파일 점검 (/etc/systemd/system) ---
SYSTEMD_DIR="/etc/systemd/system"

if [ -d "$SYSTEMD_DIR" ]; then
    # 동일한 로직 적용 (심볼릭 링크 추적 필수)
    VULN_SYSTEMD=$(find -L "$SYSTEMD_DIR" -type f \( ! -user root -o -perm -o+w \) -print -quit 2>/dev/null)
    
    if [ -z "$VULN_SYSTEMD" ]; then
        U_17_2=0
    else
        U_17_2=1
    fi
else
    # 디렉터리가 없으면 양호
    U_17_2=0
fi

# --- 전체 결과 집계 ---
if [ $U_17_1 -eq 1 ] || [ $U_17_2 -eq 1 ]; then
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
    "flag_id": "U-17",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_17_1": $U_17_1,
      "U_17_2": $U_17_2
    },
    "timestamp": "$DATE"
  }
}
EOF