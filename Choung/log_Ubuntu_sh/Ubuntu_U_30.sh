#!/bin/bash

# [U-30] UMASK 설정 관리
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-30"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_30_1=0; U_30_2=0; IS_VUL=0

# 1. [U_30_1] 현재 쉘 및 /etc/profile 점검
# 1-1. 현재 umask 확인
CUR_UMASK=$(run_cmd "[U_30_1] 현재 쉘 umask 확인" "umask")
# 원본 로직: group(2번째자리) < 2 OR other(3번째자리) < 2 이면 취약
G_VAL=${CUR_UMASK: -2:1}
O_VAL=${CUR_UMASK: -1:1}

if [[ "$G_VAL" -lt 2 || "$O_VAL" -lt 2 ]]; then
    U_30_1=1
    log_basis "[U_30_1] 현재 쉘 umask($CUR_UMASK) 설정 미흡 (022 이상이어야 함)" "취약"
fi

# 1-2. /etc/profile 점검
PROFILE="/etc/profile"
if [[ -f "$PROFILE" ]]; then
    # umask 설정이 있는지 확인
    P_CHECK=$(run_cmd "[U_30_1] $PROFILE 내 umask 설정 확인" "grep -vE '^#|^\s#' '$PROFILE' | grep -i 'umask' || echo 'none'")
    if [[ "$P_CHECK" != "none" ]]; then
        VALS=$(echo "$P_CHECK" | awk -F= '{print $2}' | awk '{print $1}' | tr -d ' ')
        for v in $VALS; do
            if [[ ${#v} -ge 3 ]]; then
                g=${v: -2:1}; o=${v: -1:1}
                if [[ "$g" -lt 2 || "$o" -lt 2 ]]; then
                    U_30_1=1
                    log_basis "[U_30_1] $PROFILE 내 취약한 umask 설정($v) 발견" "취약"
                fi
            elif [[ "$v" -lt 22 ]]; then # 2자리 숫자일 경우
                 U_30_1=1
                 log_basis "[U_30_1] $PROFILE 내 취약한 umask 설정($v) 발견" "취약"
            fi
        done
    fi
else
    run_cmd "[U_30_1] $PROFILE 파일 확인" "ls $PROFILE 2>/dev/null || echo '없음'"
fi

if [[ $U_30_1 -eq 0 ]]; then
    log_basis "[U_30_1] 쉘 및 프로필 umask 설정 양호" "양호"
fi


# 2. [U_30_2] /etc/login.defs 점검
LOGIN_DEFS="/etc/login.defs"
if [[ -f "$LOGIN_DEFS" ]]; then
    L_CHECK=$(run_cmd "[U_30_2] $LOGIN_DEFS 내 umask 설정 확인" "grep -vE '^#|^\s#' '$LOGIN_DEFS' | grep -i 'UMASK' | awk '{print \$2}' || echo 'none'")
    if [[ "$L_CHECK" != "none" ]]; then
        for v in $L_CHECK; do
             if [[ ${#v} -ge 3 ]]; then
                g=${v: -2:1}; o=${v: -1:1}
                if [[ "$g" -lt 2 || "$o" -lt 2 ]]; then
                    U_30_2=1
                    log_basis "[U_30_2] $LOGIN_DEFS 내 취약한 UMASK 설정($v) 발견" "취약"
                fi
             elif [[ "$v" -lt 22 ]]; then
                 U_30_2=1
                 log_basis "[U_30_2] $LOGIN_DEFS 내 취약한 UMASK 설정($v) 발견" "취약"
             fi
        done
    fi
else
    run_cmd "[U_30_2] $LOGIN_DEFS 파일 확인" "ls $LOGIN_DEFS 2>/dev/null || echo '없음'"
fi

if [[ $U_30_2 -eq 0 ]]; then
    log_basis "[U_30_2] login.defs umask 설정 양호" "양호"
fi

if [[ $U_30_1 -eq 1 || $U_30_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_30_1": $U_30_1,
      "U_30_2": $U_30_2
    },
    "timestamp": "$DATE"
  }
}
EOF
