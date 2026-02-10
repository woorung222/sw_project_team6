#!/bin/bash

# 점검 내용 : 가이드 사례에 따른 시스템 로깅 설정 적정성 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

U_66=0
VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-66] 점검 시작: 정책에 따른 시스템 로깅 설정"

# [Step 1] 설정 파일 경로 확인
# 가이드 사례: /etc/rsyslog.conf 또는 /etc/rsyslog.d/ 디렉토리 내 설정 확인
RS_CONF="/etc/rsyslog.conf"
RS_DIR="/etc/rsyslog.d"

echo "▶ [LINUX] 진입: 가이드 명시 로그 정책 확인"

# 점검해야 할 가이드 기준 설정 리스트
# 1. *.info;mail.none;authpriv.none;cron.none
# 2. auth,authpriv.*
# 3. mail.*
# 4. cron.*
# 5. *.alert
# 6. *.emerg

CHECK_ITEMS=(
    "\*\.info;mail\.none;authpriv\.none;cron\.none"
    "auth,authpriv\.\*"
    "mail\.\*"
    "cron\.\*"
    "\*\.alert"
    "\*\.emerg"
)

MISSING_COUNT=0

for item in "${CHECK_ITEMS[@]}"; do
    # 메인 설정 파일 및 하위 설정 파일들 전체에서 검색 (주석 제외)
    # sudo를 사용하여 권한 문제 해결
    FOUND=$(sudo grep -rE "^[^#]*$item" "$RS_CONF" "$RS_DIR" 2>/dev/null)
    
    if [ -z "$FOUND" ]; then
        echo "  - [미흡] 설정 누락: $item"
        ((MISSING_COUNT++))
    else
        echo "  - [확인] 설정 존재: $item"
    fi
done

# 최종 판정: 가이드 사례의 설정 중 누락된 것이 있으면 취약
if [ "$MISSING_COUNT" -gt 0 ]; then
    echo ""
    echo "▶ 결과: [ 취약 ] 가이드에서 권고하는 로그 설정이 일부 누락되었습니다."
    U_66=1
else
    echo ""
    echo "▶ 결과: [ 양호 ] 가이드의 모든 로그 기록 정책이 설정되어 있습니다."
    U_66=0
fi

echo "----------------------------------------------------"
echo "U_66 : $U_66"

# 최종 결과 출력
if [ $U_66 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정: /etc/rsyslog.conf 내 가이드 기준 로그 정책 보완 필요"
fi

exit $FINAL_RESULT
