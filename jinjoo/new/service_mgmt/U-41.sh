#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : automountd(autofs) 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_41_1 : 현재 실행 중인 automountd 프로세스 점검
# U_41_2 : 시스템 시작 시 자동 실행 설정(부팅 시 활성화) 점검
U_41_1=0
U_41_2=0

# --- 3. 점검 로직 수행 ---

# [Step 1] automountd 서비스 실행 여부 확인
# 명령어: ps -ef | grep automount
AUTOMOUNT_PS=$(ps -ef | grep -iE "automount|autofs" | grep -v "grep")

if [ -n "$AUTOMOUNT_PS" ]; then
    U_41_1=1
fi

# [Step 2] 시작 스크립트 내 서비스 활성 여부 확인
# 2-1. 레거시 init 스크립트 (rc.d) 확인
RC_CHECK=$(ls -l /etc/rc*.d/S* 2>/dev/null | grep -E "amd|autofs")

# 2-2. Systemd 유닛 상태 확인
SYSTEMD_CHECK=$(systemctl list-unit-files 2>/dev/null | grep -iE "autofs|automount" | grep "enabled")

if [ -n "$RC_CHECK" ] || [ -n "$SYSTEMD_CHECK" ]; then
    U_41_2=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_41_1" -eq 1 ] || [ "$U_41_2" -eq 1 ]; then
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
    "flag_id": "U-41",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_41_1": $U_41_1,
      "U_41_2": $U_41_2
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
