#!/bin/bash

# [U-23] SUID, SGID, Sticky bit 설정 파일 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 주요 불필요 대상 파일(dump, restore, at 등)에 SUID/SGID가 설정된 경우 취약

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_23_1=0 
IS_VUL=0
VULN_DETAILS=""

# --- 점검 시작 ---

# 점검할 '불필요한' SUID/SGID 의심 파일 목록
# 일반적으로 서버 보안 가이드에서 제거를 권고하는 파일들입니다.
# (시스템 환경에 따라 사용해야 할 수도 있으므로 관리자 확인 필요)
CHECK_FILES=(
    "/sbin/dump"
    "/usr/sbin/dump"
    "/sbin/restore"
    "/usr/sbin/restore"
    "/usr/bin/at"
    "/usr/bin/lpq"
    "/usr/bin/lpr"
    "/usr/bin/lprm"
)

# 전체 시스템 검색(find / ...)은 시간이 오래 걸리고 오탐이 많으므로
# 위 목록을 기반으로 점검합니다.

for FILE in "${CHECK_FILES[@]}"; do
    if [ -f "$FILE" ]; then
        # -u: SUID 확인, -g: SGID 확인
        if [ -u "$FILE" ] || [ -g "$FILE" ]; then
            U_23_1=1
            PERM=$(stat -c "%a" "$FILE")
            VULN_DETAILS="$VULN_DETAILS $FILE($PERM)"
        fi
    fi
done

# --- 전체 결과 집계 ---
IS_VUL=$U_23_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-23",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_23_1": $U_23_1
    },
    "timestamp": "$DATE"
  }
}
EOF