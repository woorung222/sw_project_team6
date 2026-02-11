#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : DNS 서비스의 취약한 동적 업데이트 설정 여부 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_51_1 : [DNS 동적 업데이트가 필요하지 않은 경우] (취약 여부 판별용)
# U_51_2 : [DNS 동적 업데이트가 필요한 경우] (취약 여부 판별용)
U_51_1=0
U_51_2=0

# --- 3. 점검 로직 수행 ---

NAMED_CONF="/etc/bind/named.conf.options"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/named.conf"

if [ -f "$NAMED_CONF" ]; then
    # allow-update 설정 확인 (주석 제외)
    # grep -r로 하위 include 파일까지 확인하는 것이 좋으나, 여기선 주 설정파일 기준
    ALLOW_UPDATE=$(grep -r "allow-update" "$NAMED_CONF" | grep -v "^#")

    if [ -n "$ALLOW_UPDATE" ]; then
        # 설정이 존재하는 경우 분석
        if echo "$ALLOW_UPDATE" | grep -q "{.*none;.*}"; then
            # none으로 설정된 경우 (양호)
            U_51_1=0
        else
            # none이 아닌 경우 (IP 제한 또는 any 확인)
            if echo "$ALLOW_UPDATE" | grep -q "any"; then
                # any로 설정된 경우 (취약)
                U_51_2=1
            else
                # 특정 IP로 제한된 경우 (양호)
                U_51_2=0
            fi
        fi
    else
        # allow-update 설정 자체가 없는 경우 (기본값 확인 필요하나, 보통 제한됨)
        # 명시적 설정 부재를 양호로 볼지 취약으로 볼지는 정책에 따라 다름.
        # 여기서는 기존 로직에 따라 '정보' 수준으로 보고 0 유지.
        U_51_1=0
    fi
else
    # 설정 파일 없음 (서비스 미사용으로 간주 -> 양호)
    U_51_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_51_1" -eq 1 ] || [ "$U_51_2" -eq 1 ]; then
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
    "flag_id": "U-51",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_51_1": $U_51_1,
      "U_51_2": $U_51_2
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
