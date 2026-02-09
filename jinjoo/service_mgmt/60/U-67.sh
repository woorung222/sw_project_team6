#!/bin/bash

# 점검 내용 : /var/log 내 모든 로그 파일의 소유자 및 권한 전수 점검
# 대상 : Ubuntu 24.04.3 (전체 파일 검사 기준)

U_67=0
VULN_COUNT=0

echo "----------------------------------------------------"
echo "[U-67] 점검 시작: 로그 파일 소유자 및 권한 설정 (전수 조사)"

LOG_DIR="/var/log"

echo "▶ [LINUX] 진입: $LOG_DIR 내 모든 파일 검사 중..."

# [Step 1] find 명령어를 사용하여 /var/log 내의 모든 일반 파일(-type f)을 전수 조사
# - 소유자가 root가 아니거나 (-not -user root)
# - 권한이 644를 초과하는 (-perm /022) 파일들을 추출
VULN_LIST=$(sudo find "$LOG_DIR" -type f \( -not -user root -o -perm /022 \) 2>/dev/null)

if [ -n "$VULN_LIST" ]; then
    echo "▶ 결과: [ 취약 ] 보안 기준을 위반하는 로그 파일이 발견되었습니다."
    echo "----------------------------------------------------"
    echo "  [위반 파일 목록 (일부)]"
    # 목록이 너무 길 수 있으므로 상위 10개만 출력
    echo "$VULN_LIST" | head -n 10
    
    VULN_COUNT=$(echo "$VULN_LIST" | wc -l)
    echo "  ... 총 $VULN_COUNT 개의 위반 파일 발견"
    echo "----------------------------------------------------"
    U_67=1
else
    echo "▶ 결과: [ 양호 ] $LOG_DIR 내 모든 파일의 소유자가 root이며 권한이 644 이하입니다."
    U_67=0
fi

echo ""
echo "U_67 : $U_67"

# 최종 판정
if [ $U_67 -eq 0 ]; then
    echo "최종 점검 결과: [ 양호 ]"
else
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 조치 권고: 위반된 로그 파일들의 소유권을 root로 변경하고 권한을 644로 조정하십시오."
fi

exit $U_67
