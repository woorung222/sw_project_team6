#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : 서버 시각 동기화 설정 및 가동 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_65_1 : [System] 시간 동기화 패키지(chrony, ntp, systemd-timesyncd) 미설치
# U_65_2 : [Chrony] 서비스 비활성 또는 동기화 서버 미설정
# U_65_3 : [NTP] 서비스 비활성 또는 동기화 서버 미설정
U_65_1=0
U_65_2=0
U_65_3=0

# --- 3. 점검 로직 수행 ---

# [상태 확인용 변수]
HAS_CHRONY=0
HAS_NTP=0
HAS_TIMESYNCD=0

# 1. 패키지 설치 및 활성화 여부 확인
# Chrony 확인
if command -v chronyd >/dev/null 2>&1 || dpkg -l | grep -q "chrony"; then
    HAS_CHRONY=1
fi
# NTP 확인
if command -v ntpd >/dev/null 2>&1 || dpkg -l | grep -q "ntp"; then
    HAS_NTP=1
fi
# Systemd-timesyncd 확인 (Ubuntu 기본)
if systemctl is-active --quiet systemd-timesyncd; then
    HAS_TIMESYNCD=1
fi

# [U_65_1 점검] : 시간 동기화 관련 패키지가 하나라도 설치되어 있는지 확인
# 셋 다 없으면 취약
if [ "$HAS_CHRONY" -eq 0 ] && [ "$HAS_NTP" -eq 0 ] && [ "$HAS_TIMESYNCD" -eq 0 ]; then
    U_65_1=1
fi

# [U_65_2 점검] : Chrony 사용 시 설정 점검
if [ "$HAS_CHRONY" -eq 1 ]; then
    # 1. 서비스가 활성화(active) 상태인지 확인
    if ! systemctl is-active --quiet chrony; then
        U_65_2=1
    else
        # 2. 동기화 서버 설정 확인 (chrony.conf 내 server 또는 pool 지시어)
        CHRONY_CONF="/etc/chrony/chrony.conf"
        if [ -f "$CHRONY_CONF" ]; then
            if ! grep -E "^server|^pool" "$CHRONY_CONF" | grep -v "^#" >/dev/null 2>&1; then
                U_65_2=1
            fi
        else
            # 설정 파일이 없으면 취약
            U_65_2=1
        fi
    fi
fi

# [U_65_3 점검] : NTP 사용 시 설정 점검
if [ "$HAS_NTP" -eq 1 ]; then
    # 1. 서비스가 활성화(active) 상태인지 확인 (ntp 또는 ntpd)
    if ! systemctl is-active --quiet ntp && ! systemctl is-active --quiet ntpd; then
        U_65_3=1
    else
        # 2. 동기화 서버 설정 확인 (ntp.conf 내 server 또는 pool 지시어)
        NTP_CONF="/etc/ntp.conf"
        if [ -f "$NTP_CONF" ]; then
            if ! grep -E "^server|^pool" "$NTP_CONF" | grep -v "^#" >/dev/null 2>&1; then
                U_65_3=1
            fi
        else
            # 설정 파일이 없으면 취약
            U_65_3=1
        fi
    fi
fi

# --- 4. 최종 취약 여부 판단 ---
# U_65_1이 1이면(아무것도 없음) 취약
# U_65_2 또는 U_65_3이 1이면(설치됐는데 설정/구동 불량) 취약
if [ "$U_65_1" -eq 1 ] || [ "$U_65_2" -eq 1 ] || [ "$U_65_3" -eq 1 ]; then
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
    "flag_id": "U-65",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "log",
    "flag": {
      "U_65_1": $U_65_1,
      "U_65_2": $U_65_2,
      "U_65_3": $U_65_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
