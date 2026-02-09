#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : r-services(rlogin, rsh, rexec) 관련 패키지 및 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

U_36_1=0  # [/etc/inetd.conf] 설정 점검
U_36_2=0  # [/etc/xinetd.d/] 설정 점검
U_36_3=0  # [systemd] 서비스 유닛 점검
U_36_4=0  # [Package] r-services 관련 패키지 설치 여부

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-36] 점검 시작: r 계정 서비스 비활성화"

# [U_36_1] /etc/inetd.conf 점검
if [ -f "/etc/inetd.conf" ]; then
    if sudo grep -E "^\s*(login|shell|exec)\s+" /etc/inetd.conf | grep -v "^#" > /dev/null; then
        echo "▶ inetd 설정: [ 취약 ] (login/shell/exec 활성)"
        U_36_1=1; VULN_FLAGS="$VULN_FLAGS U_36_1"
    else
        echo "▶ inetd 설정: [ 양호 ]"
    fi
else
    echo "▶ inetd 설정: [ 양호 ] (설정 파일 미존재)"
fi

# [U_36_2] /etc/xinetd.d/ 점검
if [ -d "/etc/xinetd.d" ]; then
    X_CHECK=$(sudo grep -rEi "disable.*=.*no" /etc/xinetd.d/ 2>/dev/null | grep -E "(rlogin|rsh|rexec)")
    if [ -n "$X_CHECK" ]; then
        echo "▶ xinetd 설정: [ 취약 ] (rlogin/rsh/rexec 활성)"
        U_36_2=1; VULN_FLAGS="$VULN_FLAGS U_36_2"
    else
        echo "▶ xinetd 설정: [ 양호 ]"
    fi
else
    echo "▶ xinetd 설정: [ 양호 ] (디렉터리 미존재)"
fi

# [U_36_3] systemd 서비스 점검
R_UNITS=$(systemctl list-unit-files 2>/dev/null | grep -E "(rlogin|rsh|rexec|shell.target|login.target|exec.target)" | grep "enabled")
if [ -n "$R_UNITS" ]; then
    echo "▶ systemd 설정: [ 취약 ] (활성화된 유닛 발견)"
    U_36_3=1; VULN_FLAGS="$VULN_FLAGS U_36_3"
else
    echo "▶ systemd 설정: [ 양호 ]"
fi

# [U_36_4] 패키지 설치 여부 점검 (귀하의 우려사항 반영)
# rsh-server, rsh-redone-server, rsh-client 등 관련 패키지 전수 조사
echo "[INFO] r-services 관련 패키지 설치 여부 확인 중..."
R_PKGS=$(dpkg -l | grep -E "rsh-server|rsh-redone-server|rsh-client|rlogin|rexec" | grep "^ii" | awk '{print $2}')

if [ -n "$R_PKGS" ]; then
    echo "▶ 패키지 점검: [ 취약 ] 관련 패키지가 설치되어 있습니다. ($R_PKGS)"
    U_36_4=1; VULN_FLAGS="$VULN_FLAGS U_36_4"
else
    echo "▶ 패키지 점검: [ 양호 ] 관련 패키지가 설치되지 않았습니다."
fi

echo "----------------------------------------------------"
echo "U_36_1 : $U_36_1"
echo "U_36_2 : $U_36_2"
echo "U_36_3 : $U_36_3"
echo "U_36_4 : $U_36_4"

if [[ $U_36_1 -eq 0 && $U_36_2 -eq 0 && $U_36_3 -eq 0 && $U_36_4 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미설정 서비스 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
