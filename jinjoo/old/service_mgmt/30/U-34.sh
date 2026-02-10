#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : Finger 서비스 활성화 여부 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_34=0  

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-34] 점검 시작: Finger 서비스 비활성화"

# [Step 1] Finger 관련 패키지 설치 여부 확인
# Ubuntu 환경에서 주로 사용되는 finger 데몬 패키지들 조사
FINGER_PKGS=$(dpkg -l | grep -E "fingerd|cfingerd|efingerd" | awk '{print $2}')

# [Step 2] 실행 중인 포트(79) 확인
# netstat을 통해 79번 포트가 LISTEN 상태인지 확인 (audit 사용자의 sudo 권한 활용)
FINGER_PORT=$(sudo netstat -antp 2>/dev/null | grep ":79 " | grep "LISTEN")

# [Step 3] 가이드 기준 판단
# 패키지가 설치되어 있거나 실제 서비스 포트가 열려 있는 경우 취약으로 간주
if [ -n "$FINGER_PKGS" ] || [ -n "$FINGER_PORT" ]; then
    echo "▶ Finger 서비스 상태: [ 취약 ]"
    [ -n "$FINGER_PKGS" ] && echo "  - 설치된 패키지: $FINGER_PKGS"
    [ -n "$FINGER_PORT" ] && echo "  - 활성화된 포트: 79 (LISTEN)"
    U_34=1
    VULN_FLAGS="U_34"
else
    echo "▶ Finger 서비스 상태: [ 양호 ] 서비스가 설치되지 않았거나 비활성 상태입니다."
    U_34=0
fi

echo "----------------------------------------------------"
echo "U_34 : $U_34"

# 최종 판정 및 취약 플래그 리스트 출력
if [[ $U_34 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미설정 서비스 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
