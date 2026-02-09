#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : DoS 공격에 이용 가능한 서비스(echo, discard, daytime, chargen, ntp, snmp, dns, smtp) 비활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_38_1=0  # [/etc/inetd.conf] 내 취약 서비스 활성 여부
U_38_2=0  # [/etc/xinetd.d/] 내 취약 서비스 활성 여부
U_38_3=0  # [systemd] 유닛 활성화 여부
U_38_4=0  # [Port] 포트(7, 9, 13, 19, 123, 161, 53, 25) 오픈 여부

VULN_FLAGS=""
# 점검 서비스 키워드 정의
DOS_SERVICES="echo|discard|daytime|chargen|ntp|snmp|dns|named|bind|smtp|sendmail|postfix"
# 점검 포트 정의 (7, 9, 13, 19, 123, 161, 53, 25)
DOS_PORTS_REGEX=":(7|9|13|19|123|161|53|25) "

echo "----------------------------------------------------"
echo "[U-38] 점검 시작: DoS 공격에 취약한 서비스 비활성화"

# [Step 1] /etc/inetd.conf 설정 확인
if [ -f "/etc/inetd.conf" ]; then
    INETD_DOS=$(sudo grep -v "^#" /etc/inetd.conf | grep -iE "$DOS_SERVICES")
    if [ -n "$INETD_DOS" ]; then
        echo "▶ 1. inetd.conf: [ 취약 ] DoS 취약 서비스 설정 발견"
        U_38_1=1; VULN_FLAGS="$VULN_FLAGS U_38_1"
    else
        echo "▶ 1. inetd.conf: [ 양호 ]"
    fi
else
    echo "▶ 1. inetd.conf: [ 양호 ] (파일 미존재)"
fi

# [Step 2] /etc/xinetd.d/ 설정 확인
if [ -d "/etc/xinetd.d" ]; then
    XINETD_DOS=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -iE "$DOS_SERVICES")
    if [ -n "$XINETD_DOS" ]; then
        echo "▶ 2. xinetd.d: [ 취약 ] DoS 취약 서비스 설정 발견"
        U_38_2=1; VULN_FLAGS="$VULN_FLAGS U_38_2"
    else
        echo "▶ 2. xinetd.d: [ 양호 ]"
    fi
else
    echo "▶ 2. xinetd.d: [ 양호 ] (디렉터리 미존재)"
fi

# [Step 3] systemd 서비스 유닛 확인
# ntp, snmp, dns(named/bind), smtp(postfix/sendmail) 유닛 상태 통합 점검
SYSTEMD_DOS=$(systemctl list-unit-files 2>/dev/null | grep -iE "$DOS_SERVICES|chrony" | grep "enabled")
if [ -n "$SYSTEMD_DOS" ]; then
    echo "▶ 3. systemd: [ 취약 ] 활성화된 DoS 취약 서비스 유닛 발견"
    echo "  - 발견된 유닛: $(echo "$SYSTEMD_DOS" | awk '{print $1}' | xargs)"
    U_38_3=1; VULN_FLAGS="$VULN_FLAGS U_38_3"
else
    echo "▶ 3. systemd: [ 양호 ]"
fi

# [Step 4] 실제 오픈된 포트 확인 (TCP/UDP 통합)
DOS_ACTIVE_PORTS=$(sudo netstat -antup 2>/dev/null | grep -E "$DOS_PORTS_REGEX" | grep -E "LISTEN|UDP")
if [ -n "$DOS_ACTIVE_PORTS" ]; then
    echo "▶ 4. 포트 점검: [ 취약 ] DoS 관련 서비스 포트가 열려 있습니다."
    echo "  - 오픈 포트 내역:"
    echo "$DOS_ACTIVE_PORTS"
    U_38_4=1; VULN_FLAGS="$VULN_FLAGS U_38_4"
else
    echo "▶ 4. 포트 점검: [ 양호 ]"
fi

echo "----------------------------------------------------"
echo "U_38_1 : $U_38_1"
echo "U_38_2 : $U_38_2"
echo "U_38_3 : $U_38_3"
echo "U_38_4 : $U_38_4"

# 최종 판정
if [[ $U_38_1 -eq 0 && $U_38_2 -eq 0 && $U_38_3 -eq 0 && $U_38_4 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미설정 서비스 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
