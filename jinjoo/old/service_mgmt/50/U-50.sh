#!/bin/bash

# 점검 내용 : Secondary Name Server로만 Zone 정보 전송 제한 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

U_50=0  # DNS Zone Transfer 설정 점검 통합 플래그

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-50] 점검 시작: DNS Zone Transfer 설정"

# [Step 1] xfrnets 설정 확인
# 가이드 사례 명령어: cat /etc/named.boot | grep xfrnets 등
echo "[Step 1] 구형 설정 파일(named.boot) 내 xfrnets 설정 확인"
NAMED_BOOT="/etc/named.boot"
[ ! -f "$NAMED_BOOT" ] && NAMED_BOOT="/etc/bind/named.boot"

if [ -f "$NAMED_BOOT" ]; then
    XFRNETS_CHECK=$(grep -i "xfrnets" "$NAMED_BOOT")
    if [ -n "$XFRNETS_CHECK" ]; then
        echo "  - 발견된 설정: $XFRNETS_CHECK"
    else
        echo "  - xfrnets 설정이 존재하지 않습니다."
    fi
else
    echo "  - named.boot 파일이 존재하지 않습니다."
fi

# [Step 2] allow-transfer 설정 확인
# 가이드 사례 명령어: cat /etc/named.conf | grep allow-transfer 등
echo ""
echo "[Step 2] 현대적 설정 파일(named.conf) 내 allow-transfer 설정 확인"
NAMED_CONF="/etc/named.conf"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf"
[ ! -f "$NAMED_CONF" ] && NAMED_CONF="/etc/bind/named.conf.options"

if [ -f "$NAMED_CONF" ]; then
    # allow-transfer 설정 확인
    ALLOW_TRANSFER=$(grep -r "allow-transfer" "$NAMED_CONF" | grep -v "^#")
    
    if [ -n "$ALLOW_TRANSFER" ]; then
        # any 또는 주석 처리되지 않은 모든 허용이 있는지 검사
        VULN_CHECK=$(echo "$ALLOW_TRANSFER" | grep "any")
        if [ -n "$VULN_CHECK" ]; then
            echo "▶ 결과: [ 취약 ] Zone Transfer가 모든 사용자(any)에게 허용되어 있습니다."
            U_50=1; VULN_FLAGS="U_50"
        else
            echo "▶ 결과: [ 양호 ] Zone Transfer가 특정 IP로 제한되어 있습니다."
            echo "  - 설정 내용: $ALLOW_TRANSFER"
        fi
    else
        echo "▶ 결과: [ 취약 ] allow-transfer 설정이 누락되어 있어 기본적으로 모든 사용자에게 전송될 위험이 있습니다."
        U_50=1; VULN_FLAGS="U_50"
    fi
else
    echo "▶ 결과: [ 양호 ] DNS 설정 파일이 존재하지 않아 점검 대상이 아닙니다."
fi

echo ""
echo "----------------------------------------------------"
echo "U_50 : $U_50"

# 최종 판정
# 판단 기준: Zone Transfer를 허가된 사용자에게만 허용한 경우 양호
if [ $U_50 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
