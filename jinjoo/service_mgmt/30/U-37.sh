#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : cron 및 at 관련 파일(명령어, 작업 목록, 설정 파일)의 소유자 및 권한 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_37_1=0  # cron 관련 (명령어, 작업 목록 파일, 관련 설정 파일)
U_37_2=0  # at 관련 (명령어, 작업 목록 파일)

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-37] 점검 시작: cron 및 at 관련 설정 보안"

# [U_37_1] Step 1: crontab, cron 작업 목록 파일, cron 관련 파일 소유자 및 권한 확인
echo "[Step 1] cron 관련 파일 소유자 및 권한 점검 중..."

# 1. crontab 명령어 실행 파일 점검
if [ -f "/usr/bin/crontab" ]; then
    OWNER=$(stat -c "%U" /usr/bin/crontab)
    # 가이드 양호 기준: 일반 사용자 실행 권한 제거 (Others -x)
    PERM_OTHERS=$(stat -c "%A" /usr/bin/crontab | cut -c 10)
    if [[ "$OWNER" != "root" ]] || [[ "$PERM_OTHERS" != "-" ]]; then
        echo "▶ /usr/bin/crontab: [ 취약 ] (소유자: $OWNER, 권한: $(stat -c "%a" /usr/bin/crontab))"
        U_37_1=1
    fi
fi

# 2. cron 작업 목록 파일 (Spool) 점검
CRON_SPOOL="/var/spool/cron/crontabs"
if [ -d "$CRON_SPOOL" ]; then
    # 가이드 양호 기준: 소유자 root, 권한 640 이하
    BAD_CRON_SPOOL=$(sudo find "$CRON_SPOOL" -type f \( ! -user root -o -perm /027 \) 2>/dev/null)
    if [ -n "$BAD_CRON_SPOOL" ]; then
        echo "▶ $CRON_SPOOL: [ 취약 ] 부적절한 권한/소유자 파일 발견"
        U_37_1=1
    fi
fi

# 3. /etc/ 내 cron 관련 설정 파일 점검
ETC_CRON_FILES=$(sudo find /etc -maxdepth 1 -name "cron*" 2>/dev/null)
for FILE in $ETC_CRON_FILES; do
    OWNER=$(stat -c "%U" "$FILE")
    PERM=$(stat -c "%a" "$FILE")
    if [[ "$OWNER" != "root" ]] || [[ "$PERM" -gt 640 ]]; then
        echo "▶ $FILE: [ 취약 ] (소유자: $OWNER, 권한: $PERM)"
        U_37_1=1
    fi
done

[ $U_37_1 -eq 1 ] && VULN_FLAGS="$VULN_FLAGS U_37_1"


# [U_37_2] Step 2: at, at 작업 목록 파일 소유자 및 권한 확인
echo ""
echo "[Step 2] at 관련 파일 소유자 및 권한 점검 중..."

# 1. at 명령어 실행 파일 점검
if [ -f "/usr/bin/at" ]; then
    OWNER=$(stat -c "%U" /usr/bin/at)
    PERM_OTHERS=$(stat -c "%A" /usr/bin/at | cut -c 10)
    if [[ "$OWNER" != "root" ]] || [[ "$PERM_OTHERS" != "-" ]]; then
        echo "▶ /usr/bin/at: [ 취약 ] (소유자: $OWNER, 권한: $(stat -c "%a" /usr/bin/at))"
        U_37_2=1
    fi
fi

# 2. at 작업 목록 파일 (Spool) 점검
AT_SPOOL="/var/spool/cron/atjobs"
if [ -d "$AT_SPOOL" ]; then
    # 가이드 양호 기준: 소유자 root, 권한 640 이하
    BAD_AT_SPOOL=$(sudo find "$AT_SPOOL" -type f \( ! -user root -o -perm /027 \) 2>/dev/null)
    if [ -n "$BAD_AT_SPOOL" ]; then
        echo "▶ $AT_SPOOL: [ 취약 ] 부적절한 권한/소유자 파일 발견"
        U_37_2=1
    fi
fi

[ $U_37_2 -eq 1 ] && VULN_FLAGS="$VULN_FLAGS U_37_2"

echo "----------------------------------------------------"
echo "U_37_1 : $U_37_1"
echo "U_37_2 : $U_37_2"

# 최종 판정
if [[ $U_37_1 -eq 0 && $U_37_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
