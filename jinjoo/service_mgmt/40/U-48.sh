#!/bin/bash

# 점검 내용 : SMTP 서비스 사용 시 expn, vrfy 명령어 사용 금지 설정 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_48_1=0  # [Sendmail] PrivacyOptions 내 noexpn, novrfy 설정 여부
U_48_2=0  # [Postfix] disable_vrfy_command 설정 여부
U_48_3=0  # [Exim] acl_smtp_vrfy, acl_smtp_expn 제한 설정 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-48] 점검 시작: expn, vrfy 명령어 제한"

# 1. [Sendmail] 점검
echo ""
echo "[1. Sendmail 점검]"
if [ -f "/etc/mail/sendmail.cf" ]; then
    echo "▶ [Sendmail] 진입: PrivacyOptions 설정 확인"
    # 가이드 사례: novrfy, noexpn 또는 goaway 옵션 설정 여부 점검
    PRIV_OPT=$(grep "PrivacyOptions" /etc/mail/sendmail.cf)
    VULN_CHECK=$(echo "$PRIV_OPT" | grep -E "novrfy|noexpn|goaway")
    
    if [ -z "$VULN_CHECK" ]; then
        echo "  - 결과: [ 취약 ] PrivacyOptions에 noexpn, novrfy 설정이 누락되어 있습니다."
        U_48_1=1; VULN_FLAGS="$VULN_FLAGS U_48_1"
    else
        echo "  - 결과: [ 양호 ] 설정이 확인되었습니다."
        echo "  - 설정 내용: $PRIV_OPT"
    fi
else
    echo "▶ [Sendmail] 진입: 설정 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 2. [Postfix] 점검
echo ""
echo "[2. Postfix 점검]"
if [ -f "/etc/postfix/main.cf" ]; then
    echo "▶ [Postfix] 진입: disable_vrfy_command 설정 확인"
    # 가이드 사례: disable_vrfy_command 옵션을 yes로 설정했는지 점검
    POSTFIX_VRFY=$(grep "disable_vrfy_command" /etc/postfix/main.cf | grep -i "yes")
    if [ -z "$POSTFIX_VRFY" ]; then
        echo "  - 결과: [ 취약 ] disable_vrfy_command 설정이 yes가 아니거나 누락되었습니다."
        U_48_2=1; VULN_FLAGS="$VULN_FLAGS U_48_2"
    else
        echo "  - 결과: [ 양호 ] vrfy 명령어가 제한되어 있습니다."
    fi
    echo "  - 참고: Postfix는 기본적으로 expn 기능을 허용하지 않습니다."
else
    echo "▶ [Postfix] 진입: 설정 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 3. [Exim] 점검
echo ""
echo "[3. Exim 점검]"
EXIM_CONF="/etc/exim/exim.conf"
[ ! -f "$EXIM_CONF" ] && EXIM_CONF="/etc/exim4/exim4.conf"

if [ -f "$EXIM_CONF" ]; then
    echo "▶ [Exim] 진입: ACL 설정 확인"
    # 가이드 사례: acl_smtp_vrfy, acl_smtp_expn 설정 제거(주석 처리) 여부 점검
    EXIM_CHECK=$(grep -E "acl_smtp_vrfy|acl_smtp_expn" "$EXIM_CONF" | grep -v "^#")
    if [ -n "$EXIM_CHECK" ]; then
        echo "  - 결과: [ 취약 ] expn 또는 vrfy 명령어가 허용(accept)되어 있습니다."
        echo "  - 설정 내용: $EXIM_CHECK"
        U_48_3=1; VULN_FLAGS="$VULN_FLAGS U_48_3"
    else
        echo "  - 결과: [ 양호 ] 명령어 제한 설정이 적절합니다."
    fi
else
    echo "▶ [Exim] 진입: 설정 파일 미존재로 [ 양호 ] 처리합니다."
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_48_1:$U_48_1, U_48_2:$U_48_2, U_48_3:$U_48_3"

# 최종 판정
# 판단 기준: noexpn, novrfy 옵션이 설정된 경우 양호
if [[ $U_48_1 -eq 0 && $U_48_2 -eq 0 && $U_48_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
