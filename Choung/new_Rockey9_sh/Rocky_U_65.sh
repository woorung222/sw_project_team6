#!/bin/bash

# [U-65] NTP 및 시각 동기화 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.164-165
# 점검 목적 : 시스템 시간을 동기화하여 로그의 정확성과 신뢰성을 확보
# 자동 조치 가능 유무 : 불가능 (동기화할 타임 서버 IP 또는 도메인 지정 필요)
# 플래그 설명:
#   U_65_1 : [System] 시간 동기화 패키지(chrony, ntp) 미설치
#   U_65_2 : [Chrony] 서비스 비활성 또는 동기화 서버 미설정
#   U_65_3 : [NTP] 서비스 비활성 또는 동기화 서버 미설정

# --- 점검 로직 시작 ---

# 초기화
U_65_1=0
U_65_2=0
U_65_3=0

# 패키지 설치 확인
PKG_CHRONY=$(rpm -qa | grep "^chrony-[0-9]")
PKG_NTP=$(rpm -qa | grep "^ntp-[0-9]")

# 1. 패키지 미설치 점검 (U_65_1)
if [[ -z "$PKG_CHRONY" ]] && [[ -z "$PKG_NTP" ]]; then
    U_65_1=1
fi

# 2. [Chrony] 점검 (U_65_2)
if [[ -n "$PKG_CHRONY" ]]; then
    # 서비스 활성화 여부
    CHRONY_ACTIVE=$(systemctl is-active chronyd 2>/dev/null)
    
    # 설정 파일 점검 (/etc/chrony.conf)
    # server 또는 pool 지시어가 주석 없이 존재하는지 확인
    CHRONY_CONF="/etc/chrony.conf"
    HAS_SERVER=0
    if [[ -f "$CHRONY_CONF" ]]; then
        if grep -E "^server|^pool" "$CHRONY_CONF" >/dev/null 2>&1; then
            HAS_SERVER=1
        fi
    fi

    # 서비스가 비활성이거나 서버 설정이 없으면 취약
    if [[ "$CHRONY_ACTIVE" != "active" ]] || [[ $HAS_SERVER -eq 0 ]]; then
        U_65_2=1
    fi
fi

# 3. [NTP] 점검 (U_65_3)
if [[ -n "$PKG_NTP" ]]; then
    # 서비스 활성화 여부
    NTP_ACTIVE=$(systemctl is-active ntpd 2>/dev/null)
    
    # 설정 파일 점검 (/etc/ntp.conf)
    NTP_CONF="/etc/ntp.conf"
    HAS_NTP_SERVER=0
    if [[ -f "$NTP_CONF" ]]; then
        if grep "^server" "$NTP_CONF" >/dev/null 2>&1; then
            HAS_NTP_SERVER=1
        fi
    fi

    # 서비스가 비활성이거나 서버 설정이 없으면 취약
    if [[ "$NTP_ACTIVE" != "active" ]] || [[ $HAS_NTP_SERVER -eq 0 ]]; then
        U_65_3=1
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_65_1 -eq 1 ]] || [[ $U_65_2 -eq 1 ]] || [[ $U_65_3 -eq 1 ]]; then
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
    "flag_id": "U-65",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "log",
    "flag": {
      "U_65_1": $U_65_1,
      "U_65_2": $U_65_2,
      "U_65_3": $U_65_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
