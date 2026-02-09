#!/bin/bash

# [U-48] expn, vrfy 명령어 제한
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.116-117
# 자동 조치 가능 유무 : 수동 조치 (설정 파일 수정)
# 플래그 설명:
#   U_48_1 : [Sendmail] PrivacyOptions 설정 미흡 (noexpn, novrfy 누락)
#   U_48_2 : [Postfix] disable_vrfy_command 미설정 (취약)
#   U_48_3 : [Exim] vrfy/expn 허용 설정 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
WARN='\033[0;33m'

echo "----------------------------------------------------------------"
echo "[U-48] expn, vrfy 명령어 제한 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 서비스 활성화 여부 확인 (점검 대상 확인용)
if ! systemctl is-active sendmail >/dev/null 2>&1 && \
   ! systemctl is-active postfix >/dev/null 2>&1 && \
   ! systemctl is-active exim >/dev/null 2>&1; then
    echo -e "${GREEN}[양호]${NC} 활성화된 SMTP 서비스가 없습니다."
    echo "----------------------------------------------------------------"
    exit 0
fi

# 1. [Sendmail] 점검 (U_48_1) - PDF p.116
if systemctl is-active sendmail >/dev/null 2>&1; then
    CF_FILE="/etc/mail/sendmail.cf"
    if [[ -f "$CF_FILE" ]]; then
        # PrivacyOptions 행 추출 (주석 제외)
        PRIV_OPTS=$(grep -v "^#" "$CF_FILE" | grep -i "PrivacyOptions")
        
        # goaway가 있거나, (noexpn AND novrfy)가 있어야 함
        if [[ "$PRIV_OPTS" == *"goaway"* ]]; then
            echo -e "${GREEN}[양호]${NC} [Sendmail] 'goaway' 옵션으로 모든 정보 노출이 차단되었습니다."
        elif [[ "$PRIV_OPTS" == *"noexpn"* ]] && [[ "$PRIV_OPTS" == *"novrfy"* ]]; then
            echo -e "${GREEN}[양호]${NC} [Sendmail] 'noexpn', 'novrfy' 옵션이 설정되어 있습니다."
        else
            VULN_STATUS=1
            VULN_FLAGS+=("U_48_1")
            echo -e "${RED}[취약]${NC} [Sendmail] PrivacyOptions에 'noexpn', 'novrfy' 또는 'goaway' 설정이 없습니다."
            echo -e "   -> 현재 설정: ${PRIV_OPTS:-설정없음}"
        fi
    else
        echo -e "${WARN}[정보]${NC} [Sendmail] 설정 파일($CF_FILE)을 찾을 수 없습니다."
    fi
fi

# 2. [Postfix] 점검 (U_48_2) - PDF p.117
if systemctl is-active postfix >/dev/null 2>&1; then
    # disable_vrfy_command 값 확인 (yes여야 함)
    # Postfix 기본값은 no이므로, 설정이 없으면 취약으로 간주
    VRFY_CONF=$(postconf -h disable_vrfy_command 2>/dev/null)
    
    if [[ "$VRFY_CONF" == "yes" ]]; then
        echo -e "${GREEN}[양호]${NC} [Postfix] VRFY 명령어가 비활성화(yes)되어 있습니다."
    else
        VULN_STATUS=1
        VULN_FLAGS+=("U_48_2")
        echo -e "${RED}[취약]${NC} [Postfix] disable_vrfy_command 설정이 'yes'가 아닙니다."
        echo -e "   -> 현재 설정: ${VRFY_CONF:-no (기본값)}"
    fi
fi

# 3. [Exim] 점검 (U_48_3) - PDF p.117
if systemctl is-active exim >/dev/null 2>&1; then
    EXIM_CONF=$(exim -bV 2>/dev/null | grep "Configuration file" | awk '{print $3}')
    if [[ -f "$EXIM_CONF" ]]; then
        # acl_smtp_vrfy = accept 또는 acl_smtp_expn = accept 가 있는지 확인
        CHECK_ACL=$(grep -E "acl_smtp_vrfy|acl_smtp_expn" "$EXIM_CONF" | grep -v "^#" | grep "accept")
        
        if [[ -n "$CHECK_ACL" ]]; then
            VULN_STATUS=1
            VULN_FLAGS+=("U_48_3")
            echo -e "${RED}[취약]${NC} [Exim] VRFY/EXPN 명령 허용(accept) 설정이 발견되었습니다."
        else
            echo -e "${GREEN}[양호]${NC} [Exim] 명시적인 VRFY/EXPN 허용 설정이 없습니다."
        fi
    else
        echo -e "${WARN}[정보]${NC} [Exim] 설정 파일을 찾을 수 없습니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "결과: ${GREEN}[양호]${NC} (SMTP 명령어 제한 설정이 안전합니다)"
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
