#!/bin/bash

# 점검 내용 : SMTP 서비스 사용 시 일반 사용자의 옵션 제한 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_46_1=0  # [Sendmail] PrivacyOptions 내 restrictqrun 설정 여부
U_46_2=0  # [Postfix] postsuper 명령어 일반 사용자 실행 권한 제거 여부
U_46_3=0  # [Exim] exiqgrep 명령어 일반 사용자 실행 권한 제거 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-46] 점검 시작: 일반 사용자의 메일 서비스 실행 방지"

# 1. [Sendmail] 점검
echo ""
echo "[1. Sendmail 점검]"
if [ -f "/etc/mail/sendmail.cf" ]; then
    echo "▶ [Sendmail] 진입: /etc/mail/sendmail.cf 설정 확인"
    # 가이드 사례: PrivacyOptions 설정에 restrictqrun 값 포함 여부 점검
    RESTRICT_CHECK=$(grep "PrivacyOptions" /etc/mail/sendmail.cf | grep "restrictqrun")
    if [ -z "$RESTRICT_CHECK" ]; then
        echo "  - 결과: [ 취약 ] PrivacyOptions에 restrictqrun 설정이 누락되어 있습니다."
        U_46_1=1; VULN_FLAGS="$VULN_FLAGS U_46_1"
    else
        echo "  - 결과: [ 양호 ] restrictqrun 옵션이 설정되어 있습니다."
        echo "  - 설정 내용: $RESTRICT_CHECK"
    fi
else
    echo "▶ [Sendmail] 진입: 설정 파일이 존재하지 않아 [ 양호 ] 처리합니다."
fi

# 2. [Postfix] 점검
echo ""
echo "[2. Postfix 점검]"
if command -v postsuper > /dev/null; then
    echo "▶ [Postfix] 진입: /usr/sbin/postsuper 명령어 권한 확인"
    # 가이드 사례: 일반 사용자(others)의 실행 권한(-x) 제거 여부 점검
    POSTSUPER_PERM=$(stat -c "%A" /usr/sbin/postsuper 2>/dev/null | cut -c 10)
    if [ "$POSTSUPER_PERM" != "-" ]; then
        echo "  - 결과: [ 취약 ] /usr/sbin/postsuper에 일반 사용자 실행 권한이 존재합니다."
        echo "  - 현재 권한: $(stat -c "%a %A" /usr/sbin/postsuper)"
        U_46_2=1; VULN_FLAGS="$VULN_FLAGS U_46_2"
    else
        echo "  - 결과: [ 양호 ] 일반 사용자의 실행 권한이 제한되어 있습니다."
    fi
else
    echo "▶ [Postfix] 진입: postsuper 명령어가 존재하지 않아 [ 양호 ] 처리합니다."
fi

# 3. [Exim] 점검
echo ""
echo "[3. Exim 점검]"
if command -v exiqgrep > /dev/null; then
    echo "▶ [Exim] 진입: /usr/sbin/exiqgrep 명령어 권한 확인"
    # 가이드 사례: 일반 사용자(others)의 실행 권한(-x) 제거 여부 점검
    EXIQGREP_PERM=$(stat -c "%A" /usr/sbin/exiqgrep 2>/dev/null | cut -c 10)
    if [ "$EXIQGREP_PERM" != "-" ]; then
        echo "  - 결과: [ 취약 ] /usr/sbin/exiqgrep에 일반 사용자 실행 권한이 존재합니다."
        echo "  - 현재 권한: $(stat -c "%a %A" /usr/sbin/exiqgrep)"
        U_46_3=1; VULN_FLAGS="$VULN_FLAGS U_46_3"
    else
        echo "  - 결과: [ 양호 ] 일반 사용자의 실행 권한이 제한되어 있습니다."
    fi
else
    echo "▶ [Exim] 진입: exiqgrep 명령어가 존재하지 않아 [ 양호 ] 처리합니다."
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_46_1:$U_46_1, U_46_2:$U_46_2, U_46_3:$U_46_3"

# 최종 판정
# 판단 기준: 일반 사용자의 메일 서비스 실행 방지가 설정된 경우 양호
if [[ $U_46_1 -eq 0 && $U_46_2 -eq 0 && $U_46_3 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
