#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NFS 서비스 이용 시 /etc/exports 파일의 권한 및 접근 제어 설정 점검
# 대상 : Ubuntu 24.04.3

U_40_1=0  # Step 1: /etc/exports 파일 소유자 및 권한 설정 점검
U_40_2=0  # Step 2: /etc/exports 파일 내 접근 허용 대상 및 권한 설정 점검

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-40] 점검 시작: NFS 접근 통제"

# [Step 1] 파일 소유자 및 권한 확인
# 명령어: ls -l /etc/exports
echo "[Step 1] /etc/exports 파일 소유자 및 권한 확인"
if [ -f "/etc/exports" ]; then
    OWNER=$(stat -c "%U" /etc/exports)
    PERM=$(stat -c "%a" /etc/exports)
    
    # 양호 기준: 소유자 root, 권한 644 이하
    if [[ "$OWNER" == "root" ]] && [[ "$PERM" -le 644 ]]; then
        echo "▶ 파일 권한: [ 양호 ] (소유자: $OWNER, 권한: $PERM)"
    else
        echo "▶ 파일 권한: [ 취약 ] (소유자: $OWNER, 권한: $PERM)"
        U_40_1=1
        VULN_FLAGS="$VULN_FLAGS U_40_1"
    fi
else
    echo "▶ 파일 권한: [ 양호 ] (/etc/exports 파일이 존재하지 않습니다.)"
fi

# [Step 2] /etc/exports 파일 내 공유 중인 디렉터리에 접근할 수 있는 사용자 및 부여 권한 확인
# 명령어: cat /etc/exports
echo ""
echo "[Step 2] 공유 디렉터리 접근 사용자 및 부여 권한 확인"
if [ -f "/etc/exports" ]; then
    EXPORT_CONTENT=$(sudo cat /etc/exports | grep -v "^#" | grep -v "^$")

    if [ -z "$EXPORT_CONTENT" ]; then
        echo "▶ 설정 내용: [ 양호 ] 공유 중인 디렉터리가 없습니다."
    else
        echo "--- 설정 내용 ---"
        echo "$EXPORT_CONTENT"
        echo "----------------"

        # 판단 기준: 접근 통제 설정 여부 (와일드카드 '*' 사용 또는 no_root_squash 옵션 확인)
        VULN_CHECK=$(echo "$EXPORT_CONTENT" | grep -E "\*\s*\(|no_root_squash")
        
        if [ -n "$VULN_CHECK" ]; then
            echo "▶ 설정 내용: [ 취약 ] 부적절한 접근 제어 설정이 발견되었습니다."
            U_40_2=1
            VULN_FLAGS="$VULN_FLAGS U_40_2"
        else
            echo "▶ 설정 내용: [ 양호 ]"
        fi
    fi
else
    echo "▶ 설정 내용: [ 양호 ] (설정 파일 미존재로 점검 대상 없음)"
fi

echo "----------------------------------------------------"
echo "U_40_1 : $U_40_1"
echo "U_40_2 : $U_40_2"

# 최종 판정
if [[ $U_40_1 -eq 0 && $U_40_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
