#!/bin/bash

# 점검 내용 : DNS 서비스의 취약한 동적 업데이트 설정 여부 점검
# 대상 : Ubuntu 24.04.3

U_51_1=0  # [DNS 동적 업데이트가 필요하지 않은 경우]
U_51_2=0  # [DNS 동적 업데이트가 필요한 경우]

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-51] 점검 시작: DNS 서비스의 취약한 동적 업데이트 설정 금지"

NAMED_CONF="/etc/bind/named.conf.options"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/named.conf"

if [ -f "$NAMED_CONF" ]; then
    echo "▶ 설정 파일 확인: $NAMED_CONF"
    ALLOW_UPDATE=$(grep -r "allow-update" "$NAMED_CONF" | grep -v "^#")

    if [ -z "$ALLOW_UPDATE" ]; then
        echo "▶ 결과: [ 정보 ] allow-update 설정이 명시되어 있지 않습니다."
    else
        echo "  - 발견된 설정: $ALLOW_UPDATE"
        if echo "$ALLOW_UPDATE" | grep -q "{.*none;.*}"; then
            echo "▶ 1. 동적 업데이트 미필요 시나리오: [ 양호 ]"
            U_51_1=0
        else
            if echo "$ALLOW_UPDATE" | grep -q "any"; then
                echo "▶ 2. 동적 업데이트 필요 시나리오: [ 취약 ] any로 설정되어 있습니다."
                U_51_2=1; VULN_FLAGS="$VULN_FLAGS U_51_2"
            else
                echo "▶ 2. 동적 업데이트 필요 시나리오: [ 양호 ] 특정 IP로 제한되어 있습니다."
                U_51_2=0
            fi
        fi
    fi
else
    echo "▶ 결과: [ 양호 ] DNS 설정 파일이 존재하지 않아 점검 대상이 아닙니다."
fi

echo "----------------------------------------------------"
echo "결과 플래그: U_51_1:$U_51_1, U_51_2:$U_51_2"

if [[ $U_51_1 -eq 0 && $U_51_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
