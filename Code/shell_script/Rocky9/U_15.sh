#!/bin/bash

# [U-15] 파일 및 디렉터리 소유자 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 소유자(nouser) 또는 그룹(nogroup)이 존재하지 않는 파일이 발견되지 않으면 양호
# 주의 : 대용량 파일 시스템의 경우 점검 시간이 다소 소요될 수 있습니다.

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_15_1=0 
IS_VUL=0

# --- 점검 시작 ---

# find 명령어 옵션 설명:
# / : 루트 디렉터리부터 시작
# -xdev : 다른 파일 시스템(네트워크 마운트 등)은 건너뛰고 현재 파티션만 검색 (가이드 기준 준수)
# \( -nouser -o -nogroup \) : 소유자가 없거나(-o) 그룹이 없는 파일 찾기
# -print -quit : 하나라도 찾으면 경로를 출력하고 즉시 종료 (속도 최적화)
# 2>/dev/null : 접근 거부 에러 메시지 제거

FOUND_FILE=$(find / -xdev \( -nouser -o -nogroup \) -print -quit 2>/dev/null)

if [ -z "$FOUND_FILE" ]; then
    # 발견된 파일이 없음 (양호)
    U_15_1=0
else
    # 소유자 없는 파일이 존재함 (취약)
    U_15_1=1
fi

# --- 최종 결과 집계 ---
IS_VUL=$U_15_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-15",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "file",
    "flag": {
      "U_15_1": $U_15_1
    },
    "timestamp": "$DATE"
  }
}
EOF