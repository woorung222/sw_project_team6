#!/bin/bash

# 점검 내용 : 취약한 버전의 메일 서비스 이용 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_45_1=0  # [Sendmail 메일 서비스를 사용하는 경우]
U_45_2=0  # [Sendmail 메일 서비스를 사용하지 않는 경우]
U_45_3=0  # [Postfix 메일 서비스를 사용하는 경우]
U_45_4=0  # [Postfix 메일 서비스를 사용하지 않는 경우]
U_45_5=0  # [Exim 메일 서비스를 사용하는 경우]
U_45_6=0  # [Exim 메일 서비스를 사용하지 않는 경우]

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-45] 점검 시작: 메일 서비스 버전 점검"

# 1. Sendmail 점검
echo ""
echo "[1. Sendmail 점검]"
if command -v sendmail > /dev/null; then
    echo "▶ [Sendmail 메일 서비스를 사용하는 경우] 진입"
    # 가이드 사례: sendmail -d0.1 -bt 명령으로 버전 확인
    SENDMAIL_VER=$(sendmail -d0.1 -bt < /dev/null 2>&1 | grep "Version")
    echo "  - 설치된 버전: $SENDMAIL_VER"
    echo "  - 결과: 버전 정보가 확인되었습니다. 최신 보안 패치 여부를 검토하십시오."
    U_45_1=0
else
    echo "▶ [Sendmail 메일 서비스를 사용하지 않는 경우] 진입"
    # 가이드 사례: systemctl 명령으로 서비스 활성화 여부 확인
    SENDMAIL_ACT=$(systemctl list-units --type=service 2>/dev/null | grep sendmail)
    if [ -n "$SENDMAIL_ACT" ]; then
        echo "  - 서비스 상태: [ 취약 ] 사용하지 않는 Sendmail 서비스가 활성화되어 있습니다."
        echo "  - 상세 유닛: $SENDMAIL_ACT"
        U_45_2=1; VULN_FLAGS="$VULN_FLAGS U_45_2"
    else
        echo "  - 서비스 상태: [ 양호 ] Sendmail 서비스가 비활성화되어 있거나 설치되지 않았습니다."
    fi
fi

# 2. Postfix 점검
echo ""
echo "[2. Postfix 점검]"
if command -v postconf > /dev/null; then
    echo "▶ [Postfix 메일 서비스를 사용하는 경우] 진입"
    # 가이드 사례: postconf mail_version 명령으로 버전 확인
    POSTFIX_VER=$(postconf -d mail_version 2>/dev/null)
    echo "  - 설치된 버전: $POSTFIX_VER"
    echo "  - 결과: 버전 정보가 확인되었습니다. 최신 보안 패치 여부를 검토하십시오."
    U_45_3=0
else
    echo "▶ [Postfix 메일 서비스를 사용하지 않는 경우] 진입"
    # 가이드 사례: ps -ef 명령으로 프로세스 및 PID 확인
    POSTFIX_PS=$(ps -ef | grep postfix | grep -v "grep")
    if [ -n "$POSTFIX_PS" ]; then
        echo "  - 프로세스 상태: [ 취약 ] 사용하지 않는 Postfix 프로세스가 구동 중입니다."
        echo "  - 상세 프로세스: $(echo "$POSTFIX_PS" | awk '{print $2, $8}')"
        U_45_4=1; VULN_FLAGS="$VULN_FLAGS U_45_4"
    else
        echo "  - 프로세스 상태: [ 양호 ] Postfix 프로세스가 구동 중이지 않거나 설치되지 않았습니다."
    fi
fi

# 3. Exim 점검
echo ""
echo "[3. Exim 점검]"
if command -v exim > /dev/null; then
    echo "▶ [Exim 메일 서비스를 사용하는 경우] 진입"
    # 가이드 사례: systemctl 명령으로 서비스 활성화 여부 확인
    EXIM_ACT=$(systemctl list-units --type=service 2>/dev/null | grep exim)
    echo "  - 서비스 상태: $EXIM_ACT"
    echo "  - 결과: 서비스 활성화가 확인되었습니다. 버전을 점검하십시오."
    U_45_5=0
else
    echo "▶ [Exim 메일 서비스를 사용하지 않는 경우] 진입"
    # 가이드 사례: ps -ef 명령으로 프로세스 및 PID 확인
    EXIM_PS=$(ps -ef | grep exim | grep -v "grep")
    if [ -n "$EXIM_PS" ]; then
        echo "  - 프로세스 상태: [ 취약 ] 사용하지 않는 Exim 프로세스가 구동 중입니다."
        echo "  - 상세 프로세스: $(echo "$EXIM_PS" | awk '{print $2, $8}')"
        U_45_6=1; VULN_FLAGS="$VULN_FLAGS U_45_6"
    else
        echo "  - 프로세스 상태: [ 양호 ] Exim 프로세스가 구동 중이지 않거나 설치되지 않았습니다."
    fi
fi

echo ""
echo "----------------------------------------------------"
echo "결과 플래그: U_45_1:$U_45_1, U_45_2:$U_45_2, U_45_3:$U_45_3, U_45_4:$U_45_4, U_45_5:$U_45_5, U_45_6:$U_45_6"

# 최종 판정
# 판단 기준: 사용하지 않는 서비스가 모두 비활성화/종료되어 있으면 양호 
if [[ $U_45_2 -eq 0 && $U_45_4 -eq 0 && $U_45_6 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
