#!/bin/bash

# [U-12] 세션 종료 시간 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 
#   U_12_1 : [bash] TMOUT 설정이 600(초) 이하인 경우 양호
#   U_12_2 : [csh] autologout 설정이 10(분) 이하인 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (0: 양호, 1: 취약)
U_12_1=0
U_12_2=0
IS_VUL=0

# --- [U_12_1] bash, ksh, sh 점검 (TMOUT) ---
# 검색 대상: /etc/profile 및 /etc/profile.d/ 내의 모든 쉘 스크립트
# 주석(#) 제외하고 TMOUT=숫자 형태 추출
# export TMOUT=600 또는 TMOUT=600 등 다양한 형태 고려
TMOUT_VAL=$(grep -rh "TMOUT=" /etc/profile /etc/profile.d/ 2>/dev/null | grep -v "^#" | awk -F= '{print $2}' | tr -d ' ' | grep -o "[0-9]*" | sort -n | head -1)

if [ -z "$TMOUT_VAL" ]; then
    # 설정이 없으면 취약
    U_12_1=1
else
    # 값이 존재하면 600초 이하인지 확인
    if [ "$TMOUT_VAL" -le 600 ]; then
        U_12_1=0
    else
        U_12_1=1
    fi
fi


# --- [U_12_2] csh 점검 (autologout) ---
# csh 설정 파일 확인: /etc/csh.login, /etc/csh.cshrc
# autologout은 '분' 단위임 (10분 = 600초)
CSH_FILES="/etc/csh.login /etc/csh.cshrc"
AUTO_VAL=""

# 파일이 존재하는 경우에만 점검
if ls $CSH_FILES 1> /dev/null 2>&1; then
    # autologout=10 또는 set autologout=10 형태 추출
    AUTO_VAL=$(grep -rh "autologout" $CSH_FILES 2>/dev/null | grep -v "^#" | awk -F= '{print $2}' | tr -d ' ' | grep -o "[0-9]*" | sort -n | head -1)
fi

# csh이 설치되어 있지 않거나 설정 파일이 없어도, 보안상 설정이 없는 것으로 간주하여 취약 처리할지,
# 해당 쉘을 안쓰니 양호로 할지 결정해야 함. 보통 설정 파일에 명시되지 않으면 취약으로 봄.
if [ -z "$AUTO_VAL" ]; then
    U_12_2=1 # 설정 없음
else
    # 10분 이하인지 확인
    if [ "$AUTO_VAL" -le 10 ]; then
        U_12_2=0
    else
        U_12_2=1
    fi
fi

# 만약 csh 자체가 설치 안되어 있다면 U_12_2는 N/A 혹은 양호 처리 가능하나,
# 가이드 기준(설정 여부)에 따라 파일에 없으면 취약으로 두는 것이 안전함.
# 여기서는 csh 바이너리가 없으면 양호(0)로 예외 처리 추가 (선택 사항)
if ! command -v csh &> /dev/null; then
    U_12_2=0
fi


# --- 전체 결과 집계 ---
if [ $U_12_1 -eq 1 ] || [ $U_12_2 -eq 1 ]; then
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
    "flag_id": "U-12",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_12_1": $U_12_1,
      "U_12_2": $U_12_2
    },
    "timestamp": "$DATE"
  }
}
EOF