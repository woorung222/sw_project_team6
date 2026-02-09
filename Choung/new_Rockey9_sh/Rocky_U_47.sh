#!/bin/bash

# [U-47] 스팸 메일 릴레이 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.113-115
# 자동 조치 가능 유무 : 수동 조치 (설정 파일 수정)
# 플래그 설명:
#   U_47_1 : [Sendmail] 릴레이 제한 설정 미흡 (버전 8.9 이상/미만 통합)
#   U_47_2 : [Postfix] Open Relay(전체 허용) 설정 발견
#   U_47_3 : [Exim] 릴레이 제한 설정 미흡

# --- 점검 로직 시작 ---

# 초기화
U_47_1=0
U_47_2=0
U_47_3=0

# 서비스 활성화 여부 확인 (전체 비활성 시 양호 유지)
if systemctl is-active sendmail >/dev/null 2>&1 || \
   systemctl is-active postfix >/dev/null 2>&1 || \
   systemctl is-active exim >/dev/null 2>&1; then

    # 1. Sendmail 점검 (U_47_1)
    if systemctl is-active sendmail >/dev/null 2>&1; then
        # 버전 확인
        RAW_VER=$(sendmail -d0.1 < /dev/null 2>&1 | grep "Version")
        VER_NUM=$(echo "$RAW_VER" | awk '{print $2}')
        
        # Major.Minor 추출
        MAJOR=$(echo "$VER_NUM" | cut -d. -f1 | tr -cd '0-9')
        MINOR=$(echo "$VER_NUM" | cut -d. -f2 | tr -cd '0-9')
        [[ -z "$MAJOR" ]] && MAJOR=0
        [[ -z "$MINOR" ]] && MINOR=0

        # 1-1. Sendmail 8.9 이상
        if [[ "$MAJOR" -gt 8 ]] || [[ "$MAJOR" -eq 8 && "$MINOR" -ge 9 ]]; then
            CF_FILE="/etc/mail/sendmail.cf"
            # promiscuous_relay 설정 여부 OR access.db 부재 시 취약
            if grep -v "^#" "$CF_FILE" 2>/dev/null | grep -i "promiscuous_relay" >/dev/null; then
                U_47_1=1
            elif [[ ! -f "/etc/mail/access.db" ]]; then
                U_47_1=1
            fi
        # 1-2. Sendmail 8.9 미만
        else
            # Relaying denied 규칙이 없으면 취약
            if ! grep -v "^#" /etc/mail/sendmail.cf 2>/dev/null | grep -q "Relaying denied"; then
                U_47_1=1
            fi
        fi
    fi

    # 2. Postfix 점검 (U_47_2)
    if systemctl is-active postfix >/dev/null 2>&1; then
        RELAY_CONF=$(postconf -n mynetworks 2>/dev/null)
        # 0.0.0.0/0 또는 * 포함 시 취약
        if [[ "$RELAY_CONF" == *"0.0.0.0/0"* ]] || [[ "$RELAY_CONF" == *"*"* ]]; then
            U_47_2=1
        fi
    fi

    # 3. Exim 점검 (U_47_3)
    if systemctl is-active exim >/dev/null 2>&1; then
        # 설정 파일 경로 찾기
        EXIM_CONF=$(exim -bV 2>/dev/null | grep "Configuration file" | awk '{print $3}')
        if [[ -f "$EXIM_CONF" ]]; then
            # relay_from_hosts 또는 accept hosts에 * 포함 시 취약
            if grep -E "relay_from_hosts|accept hosts" "$EXIM_CONF" | grep -v "^#" | grep -q "*"; then
                U_47_3=1
            fi
        fi
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_47_1 -eq 1 ]] || [[ $U_47_2 -eq 1 ]] || [[ $U_47_3 -eq 1 ]]; then
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
    "flag_id": "U-47",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flags": {
      "U_47_1": $U_47_1,
      "U_47_2": $U_47_2,
      "U_47_3": $U_47_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
