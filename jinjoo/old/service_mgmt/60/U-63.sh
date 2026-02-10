#!/bin/bash

# 점검 내용 : sudoers 파일의 권한 및 설정 적절성 점검
# 대상 : Ubuntu 24.04.3 (명령어별 sudo 권한 적용)

U_63=0
VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-63] 점검 시작: sudo 명령어 접근 관리"

SUDOERS_FILE="/etc/sudoers"

# [Step 1] 파일 존재 확인
if [ ! -f "$SUDOERS_FILE" ]; then
    echo "▶ 결과: [ 양호 ] sudoers 파일이 존재하지 않습니다."
    U_63=0
else
    echo "▶ [LINUX] 진입: /etc/sudoers 권한 및 설정 분석"

    # [Step 2] 소유자 및 권한 확인 (sudo 적용)
    # 일반 사용자가 실행하더라도 파일 정보 확인이 가능하도록 sudo 사용
    FILE_OWNER=$(sudo stat -c "%U" "$SUDOERS_FILE")
    FILE_PERM=$(sudo stat -c "%a" "$SUDOERS_FILE")

    echo "  - 파일 소유자: $FILE_OWNER (기준: root)"
    echo "  - 파일 권한: $FILE_PERM (기준: 640 이하)"

    # 판단 기준: 소유자가 root가 아니거나 권한이 640을 초과하는 경우
    if [ "$FILE_OWNER" != "root" ] || [ "$FILE_PERM" -gt 640 ]; then
        echo "  - 결과: [ 취약 ] 파일의 소유자 또는 권한 설정이 보안 기준을 초과합니다."
        U_63=1
    else
        # [Step 3] 내부 설정 확인 (sudo를 통해 파일 내용 읽기)
        # root 권한으로 grep을 수행하여 Permission denied 방지
        EXCESSIVE_SUDO=$(sudo grep -vE "^#|^root|^%sudo|^%admin|^Defaults" "$SUDOERS_FILE" | grep "ALL=(ALL" | grep "ALL")
        NOPASSWD_CHECK=$(sudo grep -v "^#" "$SUDOERS_FILE" | grep "NOPASSWD")

        if [ -n "$EXCESSIVE_SUDO" ] || [ -n "$NOPASSWD_CHECK" ]; then
            echo "  - 결과: [ 취약 ] 과도한 권한 부여(ALL) 또는 패스워드 생략(NOPASSWD) 설정이 발견되었습니다."
            U_63=1
        else
            echo "  - 결과: [ 양호 ] 파일 권한 및 내부 설정이 적절합니다."
            U_63=0
        fi
    fi
fi

echo ""
echo "----------------------------------------------------"
echo "U_63 : $U_63"

# 최종 판정
if [ $U_63 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정: sudoers 파일 보안 설정이 미비합니다."
fi

exit $FINAL_RESULT
