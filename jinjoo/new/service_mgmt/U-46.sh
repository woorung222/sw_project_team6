#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : SMTP 서비스 사용 시 일반 사용자의 옵션 제한 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_46_1 : [Sendmail] PrivacyOptions 내 restrictqrun 설정 여부
# U_46_2 : [Postfix] postsuper 명령어 일반 사용자 실행 권한 제거 여부
# U_46_3 : [Exim] exiqgrep 명령어 일반 사용자 실행 권한 제거 여부
U_46_1=0
U_46_2=0
U_46_3=0

# --- 3. 점검 로직 수행 ---

# [1. Sendmail 점검]
if [ -f "/etc/mail/sendmail.cf" ]; then
    # PrivacyOptions 설정에 restrictqrun 값 포함 여부 점검
    RESTRICT_CHECK=$(grep "PrivacyOptions" /etc/mail/sendmail.cf | grep "restrictqrun")
    if [ -z "$RESTRICT_CHECK" ]; then
        U_46_1=1
    fi
fi

# [2. Postfix 점검]
# postsuper 명령어 경로 확인
POSTSUPER_CMD=$(command -v postsuper)
if [ -n "$POSTSUPER_CMD" ]; then
    # 일반 사용자(others)의 실행 권한(x) 확인 (stat -c "%A"의 10번째 문자)
    # 예: -rwxr-xr-x -> x (취약) / -rwxr-x--- -> - (양호)
    POSTSUPER_PERM=$(stat -c "%A" "$POSTSUPER_CMD" 2>/dev/null | cut -c 10)
    if [ "$POSTSUPER_PERM" != "-" ]; then
        U_46_2=1
    fi
fi

# [3. Exim 점검]
# exiqgrep 명령어 경로 확인
EXIQGREP_CMD=$(command -v exiqgrep)
if [ -n "$EXIQGREP_CMD" ]; then
    # 일반 사용자(others)의 실행 권한(x) 확인
    EXIQGREP_PERM=$(stat -c "%A" "$EXIQGREP_CMD" 2>/dev/null | cut -c 10)
    if [ "$EXIQGREP_PERM" != "-" ]; then
        U_46_3=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_46_1" -eq 1 ] || [ "$U_46_2" -eq 1 ] || [ "$U_46_3" -eq 1 ]; then
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
    "flag_id": "U-46",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_46_1": $U_46_1,
      "U_46_2": $U_46_2,
      "U_46_3": $U_46_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
