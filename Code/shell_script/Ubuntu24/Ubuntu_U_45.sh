#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 취약한 버전의 메일 서비스 이용 여부 점검 (Sendmail, Postfix, Exim)
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_45_1 : [Sendmail] 사용 중 (버전 확인용, 취약 여부엔 미반영)
# U_45_2 : [Sendmail] 미사용 간주 시 활성화 여부 (취약 포인트)
# U_45_3 : [Postfix] 사용 중 (버전 확인용, 취약 여부엔 미반영)
# U_45_4 : [Postfix] 미사용 간주 시 활성화 여부 (취약 포인트)
# U_45_5 : [Exim] 사용 중 (버전 확인용, 취약 여부엔 미반영)
# U_45_6 : [Exim] 미사용 간주 시 활성화 여부 (취약 포인트)

U_45_1=0
U_45_2=0
U_45_3=0
U_45_4=0
U_45_5=0
U_45_6=0

# --- 3. 점검 로직 수행 ---

# [1. Sendmail 점검]
if command -v sendmail > /dev/null; then
    # 사용하는 경우 (버전 정보만 로깅)
    SENDMAIL_VER=$(sendmail -d0.1 -bt < /dev/null 2>&1 | grep "Version")
    echo "  - [Info] Sendmail 설치됨: $SENDMAIL_VER" >&2
    U_45_1=0
else
    # 사용하지 않는 경우 (서비스 활성화 여부 확인)
    SENDMAIL_ACT=$(systemctl list-units --type=service 2>/dev/null | grep sendmail)
    if [ -n "$SENDMAIL_ACT" ]; then
        echo "  - [취약] Sendmail 미사용 환경이나 서비스 활성화됨" >&2
        U_45_2=1
    fi
fi

# [2. Postfix 점검]
if command -v postconf > /dev/null; then
    # 사용하는 경우
    POSTFIX_VER=$(postconf -d mail_version 2>/dev/null)
    echo "  - [Info] Postfix 설치됨: $POSTFIX_VER" >&2
    U_45_3=0
else
    # 사용하지 않는 경우 (프로세스 확인)
    POSTFIX_PS=$(ps -ef | grep postfix | grep -v "grep")
    if [ -n "$POSTFIX_PS" ]; then
        echo "  - [취약] Postfix 미사용 환경이나 프로세스 구동 중" >&2
        U_45_4=1
    fi
fi

# [3. Exim 점검]
if command -v exim > /dev/null; then
    # 사용하는 경우
    EXIM_ACT=$(systemctl list-units --type=service 2>/dev/null | grep exim)
    echo "  - [Info] Exim 서비스 확인됨" >&2
    U_45_5=0
else
    # 사용하지 않는 경우 (프로세스 확인)
    EXIM_PS=$(ps -ef | grep exim | grep -v "grep")
    if [ -n "$EXIM_PS" ]; then
        echo "  - [취약] Exim 미사용 환경이나 프로세스 구동 중" >&2
        U_45_6=1
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
# 사용하지 않는 서비스(2, 4, 6)가 활성화되어 있는 경우 취약으로 판단
if [ "$U_45_2" -eq 1 ] || [ "$U_45_4" -eq 1 ] || [ "$U_45_6" -eq 1 ]; then
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
    "flag_id": "U-45",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_45_1": $U_45_1,
      "U_45_2": $U_45_2,
      "U_45_3": $U_45_3,
      "U_45_4": $U_45_4,
      "U_45_5": $U_45_5,
      "U_45_6": $U_45_6
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
