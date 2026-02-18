#!/bin/bash

# [U-46] 일반 사용자의 메일 서비스 실행 방지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 메일 서비스 명령어의 일반 사용자 실행 권한 제한 여부 점검
# DB 정합성 : IS_AUTO=0 (설정 변경 및 서비스 영향 위험으로 인한 수동 조치 권장)

HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정 (DB 기준: Is Auto = 0)
U_46_1=0; U_46_2=0; U_46_3=0
IS_VUL=0
IS_AUTO=0 

# 1. [U_46_1] Sendmail 점검
if [ -f "/etc/mail/sendmail.cf" ]; then
    # PrivacyOptions에 restrictqrun 옵션이 있는지 확인
    if ! grep -v "^#" /etc/mail/sendmail.cf | grep "PrivacyOptions" | grep -q "restrictqrun"; then
        U_46_1=1
    fi
fi

# 2. [U_46_2] Postfix 점검
POSTSUPER_PATH=$(command -v postsuper 2>/dev/null || echo "/usr/sbin/postsuper")
if [ -f "$POSTSUPER_PATH" ]; then
    # Other 권한에 실행(x) 비트가 포함되어 있는지 확인 (홀수면 x 포함)
    PERM=$(stat -c "%a" "$POSTSUPER_PATH")
    if [ $(( ${PERM: -1} % 2 )) -eq 1 ]; then
        U_46_2=1
    fi
fi

# 3. [U_46_3] Exim 점검
EXIQGREP_PATH=$(command -v exiqgrep 2>/dev/null || echo "/usr/sbin/exiqgrep")
if [ -f "$EXIQGREP_PATH" ]; then
    PERM=$(stat -c "%a" "$EXIQGREP_PATH")
    if [ $(( ${PERM: -1} % 2 )) -eq 1 ]; then
        U_46_3=1
    fi
fi

# 최종 결과 집계
[ "$U_46_1" -eq 1 ] || [ "$U_46_2" -eq 1 ] || [ "$U_46_3" -eq 1 ] && IS_VUL=1

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-46",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "service",
    "flag": { "U_46_1": $U_46_1, "U_46_2": $U_46_2, "U_46_3": $U_46_3 },
    "timestamp": "$DATE"
  }
}
EOF