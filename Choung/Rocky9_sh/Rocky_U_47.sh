#!/bin/bash

# [U-47] 스팸 메일 릴레이 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.113-115
# 자동 조치 가능 유무 : 수동 조치 (설정 파일 수정)
# 플래그 설명:
#   U_47_1 : [Sendmail >= 8.9] 릴레이 제한 설정 미흡
#   U_47_2 : [Sendmail < 8.9] 릴레이 차단 규칙 누락
#   U_47_3 : [Postfix] Open Relay(전체 허용) 설정 발견
#   U_47_4 : [Exim] 릴레이 제한 설정 미흡

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-47] 스팸 메일 릴레이 제한 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 서비스 활성화 여부 확인 (전체 공통)
if ! systemctl is-active sendmail >/dev/null 2>&1 && \
   ! systemctl is-active postfix >/dev/null 2>&1 && \
   ! systemctl is-active exim >/dev/null 2>&1; then
    echo -e "${GREEN}[양호]${NC} 활성화된 SMTP 서비스가 없습니다."
    echo "----------------------------------------------------------------"
    exit 0
fi

# 1. Sendmail 점검 (버전 분기)
if systemctl is-active sendmail >/dev/null 2>&1; then
    # 버전 확인
    RAW_VER=$(sendmail -d0.1 < /dev/null 2>&1 | grep "Version")
    VER_NUM=$(echo "$RAW_VER" | awk '{print $2}')
    
    # 버전 비교를 위한 Major.Minor 추출 (숫자만 추출)
    MAJOR=$(echo "$VER_NUM" | cut -d. -f1 | tr -cd '0-9')
    MINOR=$(echo "$VER_NUM" | cut -d. -f2 | tr -cd '0-9')
    
    # 변수가 비어있을 경우 대비 (기본값 0)
    [[ -z "$MAJOR" ]] && MAJOR=0
    [[ -z "$MINOR" ]] && MINOR=0
    
    echo "   -> 감지된 Sendmail 버전: $VER_NUM"

    # [수정] Bash 내장 논리 연산 사용 (서브쉘 제거)
    # 1-1. Sendmail 8.9 이상 (U_47_1)
    if [[ "$MAJOR" -gt 8 ]] || [[ "$MAJOR" -eq 8 && "$MINOR" -ge 9 ]]; then
        CF_FILE="/etc/mail/sendmail.cf"
        # 점검 1: promiscuous_relay 설정 여부
        if grep -v "^#" "$CF_FILE" | grep -i "promiscuous_relay" >/dev/null; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_47_1")
            echo -e "${RED}[취약]${NC} [Sendmail 8.9+] 'promiscuous_relay'(전체 허용) 옵션이 설정되어 있습니다."
        # 점검 2: Access DB 존재 여부
        elif [[ ! -f "/etc/mail/access.db" ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_47_1")
            echo -e "${RED}[취약]${NC} [Sendmail 8.9+] 릴레이 제어 파일(access.db)이 없습니다."
        else
            echo -e "${GREEN}[양호]${NC} [Sendmail 8.9+] 스팸 릴레이 제한 설정이 적용되어 있습니다."
        fi

    # 1-2. Sendmail 8.9 미만 (U_47_2)
    else
        # 구버전은 기본적으로 릴레이를 허용하므로, 명시적인 거부 규칙(Relaying denied)이 있어야 함
        DENY_RULE=$(grep -v "^#" /etc/mail/sendmail.cf | grep "Relaying denied")
        
        if [[ -z "$DENY_RULE" ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_47_2")
            echo -e "${RED}[취약]${NC} [Sendmail <8.9] 릴레이 차단 규칙(Relaying denied)이 설정 파일에 없습니다."
        else
            echo -e "${GREEN}[양호]${NC} [Sendmail <8.9] 릴레이 차단 규칙이 설정되어 있습니다."
        fi
    fi
fi

# 2. Postfix 점검 (U_47_3)
if systemctl is-active postfix >/dev/null 2>&1; then
    RELAY_CONF=$(postconf -n mynetworks 2>/dev/null)
    
    if [[ "$RELAY_CONF" == *"0.0.0.0/0"* ]] || [[ "$RELAY_CONF" == *"*"* ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_47_3")
        echo -e "${RED}[취약]${NC} [Postfix] mynetworks 설정이 전체 허용($RELAY_CONF)되어 있습니다."
    else
        echo -e "${GREEN}[양호]${NC} [Postfix] 릴레이 제한 설정이 적절합니다."
        [[ -n "$RELAY_CONF" ]] && echo "   -> 설정값: $RELAY_CONF"
    fi
fi

# 3. Exim 점검 (U_47_4)
if systemctl is-active exim >/dev/null 2>&1; then
    EXIM_CONF=$(exim -bV 2>/dev/null | grep "Configuration file" | awk '{print $3}')
    
    if [[ -f "$EXIM_CONF" ]]; then
        CHECK_RELAY=$(grep -E "relay_from_hosts|accept hosts" "$EXIM_CONF" | grep -v "^#" | grep "*")
        
        if [[ -n "$CHECK_RELAY" ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_47_4")
            echo -e "${RED}[취약]${NC} [Exim] 릴레이 허용 호스트에 전체 허용(*) 설정이 발견되었습니다."
        else
            echo -e "${GREEN}[양호]${NC} [Exim] 릴레이 제한 설정이 적절합니다."
        fi
    else
        echo -e "${WARN}[정보]${NC} [Exim] 설정 파일을 찾을 수 없어 점검을 생략합니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (활성화된 메일 서비스의 릴레이 설정이 안전함)"
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
