#!/bin/bash

# 점검 내용 : FTP 기본 계정에 쉘 설정 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

U_55=0  # FTP 계정 shell 제한 점검 통합 플래그

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-55] 점검 시작: FTP 계정 shell 제한"

# [Step 1] ftp 계정의 로그인 쉘 확인
# 가이드 사례 명령어: cat /etc/passwd | grep ftp
echo "[Step 1] /etc/passwd 내 ftp 계정의 쉘 설정 확인"

if grep -q "^ftp:" /etc/passwd; then
    # ftp 계정의 마지막 필드(쉘) 추출
    FTP_SHELL=$(grep "^ftp:" /etc/passwd | cut -d: -f7)
    echo "▶ 발견된 ftp 계정 쉘: $FTP_SHELL"

    # 판단 기준: /bin/false 또는 /sbin/nologin 인지 확인
    if [[ "$FTP_SHELL" == "/bin/false" || "$FTP_SHELL" == "/sbin/nologin" || "$FTP_SHELL" == "/usr/sbin/nologin" ]]; then
        echo "▶ 결과: [ 양호 ] FTP 계정에 시스템 접근 제한 쉘이 부여되어 있습니다."
        U_55=0
    else
        echo "▶ 결과: [ 취약 ] FTP 계정에 정상적인 쉘이 부여되어 있어 시스템 접근이 가능합니다."
        U_55=1
        VULN_FLAGS="U_55"
    fi
else
    echo "▶ 결과: [ 양호 ] 시스템에 ftp 기본 계정이 존재하지 않습니다."
    U_55=0
fi

echo "----------------------------------------------------"
echo "U_55 : $U_55"

# 최종 판정
# 판단 기준: FTP 계정에 /bin/false(/sbin/nologin) 쉘이 부여된 경우 양호
if [ $U_55 -eq 0 ]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $VULN_FLAGS"
fi

exit $FINAL_RESULT
