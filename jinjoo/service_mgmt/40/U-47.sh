#!/bin/bash

# 점검 내용 : SMTP 서버의 릴레이 기능 제한 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_47_1=0  # [Sendmail] 버전별 릴레이 제한 설정 여부
U_47_2=0  # [Postfix] 릴레이 정책 설정 여부
U_47_3=0  # [Exim] 릴레이 허용 네트워크 설정 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-47] 점검 시작: 스팸 메일 릴레이 제한"

# 1. [Sendmail] 점검 (버전별 분기 처리)
echo ""
echo "[1. Sendmail 점검]"
if command -v sendmail > /dev/null; then
    # 버전 정보 추출 (예: 8.15.2)
    SENDMAIL_VER_FULL=$(sendmail -d0.1 -bt < /dev/null 2>&1 | grep "Version" | awk '{print $2}')
    # 메이저.마이너 버전 추출 (예: 8.15)
    SENDMAIL_VER_MAJOR=$(echo "$SENDMAIL_VER_FULL" | cut -d. -f1,2)

    echo "▶ Sendmail 버전 확인: $SENDMAIL_VER_FULL"

    # 버전 비교 로직 (bc 명령어가 없을 경우를 대비한 문자열 비교)
    # 8.9 미만인지 확인
    IS_LEGACY=$(echo "$SENDMAIL_VER_MAJOR < 8.9" | bc -l 2>/dev/null)

    if [ "$IS_LEGACY" == "1" ]; then
        # [Sendmail 8.9 미만 버전] 사례 적용
        echo "▶ 시나리오: [Sendmail 8.9 미만 버전] 진입"
        RELAY_DENY_CHECK=$(grep "R$\*" /etc/mail/sendmail.cf 2>/dev/null | grep "Relaying denied")
        if [ -z "$RELAY_DENY_CHECK" ]; then
            echo "  - 결과: [ 취약 ] Relaying denied 설정이 누락되어 있습니다."
            U_47_1=1; VULN_FLAGS="$VULN_FLAGS U_47_1"
        else
            echo "  - 결과: [ 양호 ] Relaying denied 설정이 존재합니다."
        fi
    else
        # [Sendmail 8.9 이상 버전] 사례 적용
        echo "▶ 시나리오: [Sendmail 8.9 이상 버전] 진입"
        if [ -f "/etc/mail/sendmail.mc" ]; then
            RELAY_FEATURE=$(grep "FEATURE.*promiscuous_relay" /etc/mail/sendmail.mc)
            if [ -n "$RELAY_FEATURE" ]; then
                echo "  - 결과: [ 취약 ] FEATURE('promiscuous_relay') 설정이 활성화되어 있습니다."
                U_47_1=1; VULN_FLAGS="$VULN_FLAGS U_47_1"
            else
                echo "  - 결과: [ 양호 ] promiscuous_relay 설정이 제거되어 있습니다."
            fi
        fi
    fi
else
    echo "▶ Sendmail: 서비스가 설치되지 않아 [ 양호 ] 처리합니다."
fi

# 2. [Postfix] 점검
echo ""
echo "[2. Postfix 점검]"
if [ -f "/etc/postfix/main.cf" ]; then
    echo "▶ [Postfix] 진입: 릴레이 정책 설정 확인"
    # 가이드 사례: smtpd_recipient_restrictions 및 mynetworks 설정 확인
    POSTFIX_RELAY=$(grep -E "smtpd_recipient_restrictions|mynetworks" /etc/postfix/main.cf)
    if [ -z "$POSTFIX_RELAY" ]; then
        echo "  - 결과: [ 취약 ] 릴레이 제한 관련 설정이 발견되지 않았습니다."
        U_47_2=1; VULN_FLAGS="$VULN_FLAGS U_47_2"
    else
        echo "  - 결과: [ 양호 ] 설정이 존재합니다."
    fi
else
    echo "▶ Postfix: 설정 파일 미존재로 [ 양호 ] 처리합니다."
fi

# 3. [Exim] 점검
echo ""
echo "[3. Exim 점검]"
EXIM_CONF="/etc/exim/exim.conf"
[ ! -f "$EXIM_CONF" ] && EXIM_CONF="/etc/exim4/exim4.conf"

if [ -f "$EXIM_CONF" ]; then
    echo "▶ [Exim] 진입: 릴레이 허용 네트워크 주소 확인"
    # 가이드 사례: relay_from_hosts 또는 hosts= 설정 확인
    EXIM_RELAY=$(grep -E "relay_from_hosts|hosts=" "$EXIM_CONF")
    if [ -z "$EXIM_RELAY" ]; then
        echo "  - 결과: [ 취약 ] relay_from_hosts 설정이 누락되어 있습니다."
        U_47_3=1; VULN_FLAGS="$VULN_FLAGS U_47_3"
    else
        echo "  - 결과: [ 양호 ] 설정이 존재합니다."
    fi
else
    echo "▶ Exim: 설정 파일 미존재로 [ 양호 ] 처리합니다."
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_47_1:$U_47_1, U_47_2:$U_47_2, U_47_3:$U_47_3"

# 최종 판정
# 판단 기준: 릴레이 제한이 설정된 경우 양호 
if [[ $U_47_1 -eq 0 && $U_47_2 -eq 0 && $U_47_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
