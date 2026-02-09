#!/bin/bash

# [U-66] 정책에 따른 시스템 로깅 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.166-167
# 자동 조치 가능 유무 : 불가능 (조직의 로그 정책에 따라 설정 파일 편집 필요)
# 플래그 설명:
#   U_66_1 : [System] rsyslog 미설치 또는 서비스 비활성화
#   U_66_2 : [Config] secure(authpriv) 로그 설정 미흡
#   U_66_3 : [Config] messages(info) 로그 설정 미흡
#   U_66_4 : [Config] cron 로그 설정 미흡
#   U_66_5 : [Config] maillog(mail) 로그 설정 미흡

# --- 점검 로직 시작 ---

# 초기화
U_66_1=0
U_66_2=0
U_66_3=0
U_66_4=0
U_66_5=0

# 1. 패키지 및 서비스 상태 점검 (U_66_1)
PKG_CHECK=$(rpm -qa | grep "^rsyslog-[0-9]")
SERVICE_ACTIVE=$(systemctl is-active rsyslog 2>/dev/null)

if [[ -z "$PKG_CHECK" ]] || [[ "$SERVICE_ACTIVE" != "active" ]]; then
    U_66_1=1
fi

# 2. 설정 파일 점검
CONF_FILE="/etc/rsyslog.conf"

if [[ -f "$CONF_FILE" ]]; then
    # 주석(#)을 제거한 설정 내용만 추출 (빈 줄 포함)
    CLEAN_CONF=$(grep -v "^#" "$CONF_FILE")

    # 2-1. Secure 로그 (authpriv) -> /var/log/secure (U_66_2)
    # authpriv.* 또는 authpriv.none이 아닌 설정이 /var/log/secure로 가는지 확인
    # egrep 패턴: authpriv.* -> 임의의 공백/탭 -> /var/log/secure
    if ! echo "$CLEAN_CONF" | grep -E "authpriv\.\*[[:space:]].*\/var\/log\/secure" >/dev/null 2>&1; then
        U_66_2=1
    fi

    # 2-2. Messages 로그 (info, global) -> /var/log/messages (U_66_3)
    # *.info;mail.none;authpriv.none;cron.none                /var/log/messages
    # 핵심은 *.info 수준이 /var/log/messages로 가는지 여부
    if ! echo "$CLEAN_CONF" | grep -E "\*\.info.*\/var\/log\/messages" >/dev/null 2>&1; then
        U_66_3=1
    fi

    # 2-3. Cron 로그 (cron) -> /var/log/cron (U_66_4)
    # cron.* /var/log/cron
    if ! echo "$CLEAN_CONF" | grep -E "cron\.\*.*\/var\/log\/cron" >/dev/null 2>&1; then
        U_66_4=1
    fi

    # 2-4. Maillog (mail) -> /var/log/maillog (U_66_5)
    # mail.* -/var/log/maillog (앞에 - 붙을 수도 있음)
    # 정규식 수정: 경로 앞에 -? (하이픈 0개 또는 1개) 허용
    if ! echo "$CLEAN_CONF" | grep -E "mail\.\*.*-?\/var\/log\/maillog" >/dev/null 2>&1; then
        U_66_5=1
    fi

else
    # 설정 파일이 없으면 모든 Config 플래그를 취약 처리
    U_66_2=1
    U_66_3=1
    U_66_4=1
    U_66_5=1
fi

# 3. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_66_1 -eq 1 ]] || [[ $U_66_2 -eq 1 ]] || [[ $U_66_3 -eq 1 ]] || [[ $U_66_4 -eq 1 ]] || [[ $U_66_5 -eq 1 ]]; then
    IS_VUL=1
fi

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-66",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "log",
    "flags": {
      "U_66_1": $U_66_1,
      "U_66_2": $U_66_2,
      "U_66_3": $U_66_3,
      "U_66_4": $U_66_4,
      "U_66_5": $U_66_5
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
