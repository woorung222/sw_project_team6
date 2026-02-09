#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : /var/log 디렉터리 및 내부 로그 파일의 소유자(root) 및 권한(644) 점검
# 대상 : Ubuntu 24.04.3

# 취약점 존재 여부 (Default: 0 / 취약: 1)
U_67_1=0  # /var/log 디렉터리 자체 보안
U_67_2=0  # 내부 로그 파일 소유자 및 권한 (root / 644 이하)

VULN_FLAGS=""

echo "----------------------------------------------------"
echo "[U-67] 점검 시작: 로그 디렉터리 소유자 및 권한 설정"

# [U_67_1] /var/log 디렉터리 점검 (파일 보호를 위한 최소 요건)
DIR_OWNER=$(stat -c "%U" /var/log)
DIR_PERM=$(stat -c "%a" /var/log)

if [[ "$DIR_OWNER" == "root" ]] && [[ "$DIR_PERM" -le 755 ]]; then
    echo "▶ /var/log 디렉터리: [ 양호 ]"
    U_67_1=0
else
    echo "▶ /var/log 디렉터리: [ 취약 ] (소유자: $DIR_OWNER, 권한: $DIR_PERM)"
    U_67_1=1
    VULN_FLAGS="$VULN_FLAGS U_67_1"
fi

# [U_67_2] 내부 로그 파일 전수 점검 (root 소유 & 644 이하)
echo "[INFO] /var/log 내 로그 파일 전수 조사 중 (기준: root / 644 이하)..."

# 1. 소유자가 root가 아닌 파일 탐색
BAD_OWNER=$(sudo find /var/log -type f ! -user root 2>/dev/null)
# 2. 권한이 644를 초과하는 파일 탐색 (Others에게 쓰기 권한이 있거나 등)
# -perm /022 는 644(rw-r--r--)를 초과하여 쓰기 권한 등이 있는 경우를 탐지
BAD_PERM=$(sudo find /var/log -type f -perm /022 2>/dev/null)

if [[ -z "$BAD_OWNER" ]] && [[ -z "$BAD_PERM" ]]; then
    echo "▶ 로그 파일 점검: [ 양호 ] 모든 파일이 root 소유이며 644 이하입니다."
    U_64_2=0
else
    echo "▶ 로그 파일 점검: [ 취약 ] 가이드 기준 미흡 파일이 존재합니다."
    [ -n "$BAD_OWNER" ] && echo "  - root 외 소유자 파일 발견"
    [ -n "$BAD_PERM" ] && echo "  - 644 권한 초과 파일 발견"
    U_67_2=1
    VULN_FLAGS="$VULN_FLAGS U_67_2"
fi

echo "----------------------------------------------------"
echo "U_67_1 : $U_67_1"
echo "U_67_2 : $U_67_2"

# 최종 판정
if [[ $U_67_1 -eq 0 && $U_67_2 -eq 0 ]]; then
    FINAL_RESULT=0
    echo "최종 점검 결과: [ 양호 ]"
else
    FINAL_RESULT=1
    echo "최종 점검 결과: [ 취약 ]"
    echo "▶ 미흡 설정 플래그 리스트: $(echo $VULN_FLAGS | sed 's/^ //; s/ /, /g')"
fi

exit $FINAL_RESULT
