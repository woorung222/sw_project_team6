#!/bin/bash

# [U-44] tftp, talk 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.102-104
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_44_1 : [inetd] inetd 설정 내 해당 서비스 활성화 발견
#   U_44_2 : [xinetd] xinetd 설정 내 해당 서비스 활성화 발견
#   U_44_3 : [systemd/Process] tftp, talk, ntalk 서비스 활성화 발견

# --- 점검 로직 시작 ---

# 초기화
U_44_1=0
U_44_2=0
U_44_3=0

# 점검 대상 서비스 목록 (tftp, talk, ntalk)
TARGET_SVCS="tftp|talk|ntalk"

# 1. [inetd] 점검 (U_44_1)
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석(#) 제외하고 설정 존재 여부 확인
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "$TARGET_SVCS" >/dev/null 2>&1; then
        U_44_1=1
    fi
fi

# 2. [xinetd] 점검 (U_44_2)
if [[ -d "/etc/xinetd.d" ]]; then
    # disable = no 설정 확인
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$TARGET_SVCS" | grep -iw "no" >/dev/null 2>&1; then
        U_44_2=1
    fi
fi

# 3. [systemd/Process] 점검 (U_44_3)
# 3-1. Systemd 유닛 활성화 확인
if systemctl list-units --type service,socket 2>/dev/null | grep -E "$TARGET_SVCS" | grep -w "active" >/dev/null 2>&1; then
    U_44_3=1
fi

# 3-2. 실제 프로세스 실행 확인 (tftpd, talkd, in.tftpd 등)
if [[ $U_44_3 -eq 0 ]]; then
    PROC_LIST=("tftpd" "talkd" "in.tftpd" "in.talkd" "in.ntalkd")
    for proc in "${PROC_LIST[@]}"; do
        if ps -e -o comm | grep -xw "$proc" >/dev/null 2>&1; then
            U_44_3=1
            break
        fi
    done
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_44_1 -eq 1 ]] || [[ $U_44_2 -eq 1 ]] || [[ $U_44_3 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-44",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_44_1": $U_44_1,
      "U_44_2": $U_44_2,
      "U_44_3": $U_44_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
