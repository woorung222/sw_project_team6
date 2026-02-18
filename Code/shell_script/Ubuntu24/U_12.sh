#!/usr/bin/env bash
set -u

# =========================================================
# U_12 (상) 세션 연결 취소 (Session Timeout) | Ubuntu 24.04
# - 진단 기준: 사용자 쉘에 대한 Session Timeout(600초 이하) 설정 여부 점검
# - Rocky 논리 반영:
#   U_12_1: bash/sh (TMOUT)
#   U_12_2: csh (autologout)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_12"
CATEGORY="account"
IS_AUTO=1  # 프로필 설정 자동화 가능

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
FLAG_U_12_1=0
FLAG_U_12_2=0

# -------------------------
# 1) [U_12_1] Bash/Sh TMOUT 점검
# - /etc/profile, /etc/profile.d/*.sh 확인
# -------------------------
TMOUT_VAL=""
# grep으로 TMOUT=숫자 형태 추출 -> 숫자만 남김 -> 정렬 -> 가장 작은 값(엄격한 값) 선택
# (Ubuntu는 /etc/profile.d에 쉘 스크립트가 많으므로 -r 옵션 활용)
RAW_TMOUT=$(grep -rh "TMOUT=" /etc/profile /etc/profile.d/ 2>/dev/null | grep -v "^#" | awk -F= '{print $2}' | tr -d ' ' | grep -o "[0-9]*" | sort -n | head -1)

if [ -n "$RAW_TMOUT" ]; then
    TMOUT_VAL=$RAW_TMOUT
fi

if [ -z "$TMOUT_VAL" ]; then
    # 설정 없음 -> 취약
    FLAG_U_12_1=1
else
    # 600초(10분) 이하이면 양호
    if [ "$TMOUT_VAL" -le 600 ]; then
        FLAG_U_12_1=0
    else
        FLAG_U_12_1=1
    fi
fi

# -------------------------
# 2) [U_12_2] Csh autologout 점검
# - Ubuntu에 csh/tcsh이 안 깔려 있을 수 있으나, 설정 파일이 있다면 점검
# -------------------------
CSH_FILES="/etc/csh.login /etc/csh.cshrc"
AUTO_VAL=""

if ls $CSH_FILES 1> /dev/null 2>&1; then
    # autologout=숫자 추출 (분 단위)
    AUTO_VAL=$(grep -rh "autologout" $CSH_FILES 2>/dev/null | grep -v "^#" | awk -F= '{print $2}' | tr -d ' ' | grep -o "[0-9]*" | sort -n | head -1)
fi

# Csh 설정 파일이 없거나 설정값이 없으면 취약으로 간주 (보안 가이드 기준)
# 단, csh 미사용 시 N/A로 볼 수도 있으나 Rocky 로직에 맞춰 1(취약) 또는 0(양호) 설정
# 여기서는 "설정이 없으면 취약"이라는 Rocky 로직을 따름
if [ -z "$AUTO_VAL" ]; then
    FLAG_U_12_2=1
else
    # 10분(600초) 이하이면 양호
    if [ "$AUTO_VAL" -le 10 ]; then
        FLAG_U_12_2=0
    else
        FLAG_U_12_2=1
    fi
fi

# -------------------------
# 3) VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$FLAG_U_12_1" -eq 1 ] || [ "$FLAG_U_12_2" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# 4) Output (JSON)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_12_1": $FLAG_U_12_1,
      "U_12_2": $FLAG_U_12_2
    },
    "timestamp": "$DATE"
  }
}
EOF