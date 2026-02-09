#!/bin/bash

# [U-31] 홈디렉토리 소유자 및 권한 설정 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 홈 디렉터리 소유자가 해당 계정이고, 타 사용자(Other) 쓰기 권한이 없는 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_31_1=0 
IS_VUL=0

# --- 점검 시작 ---

# /etc/passwd 파일을 라인별로 읽음
while IFS=: read -r USERNAME _ _ _ _ HOMEDIR _; do
    
    # 1. 홈 디렉터리가 없으면 건너뜀
    if [ ! -d "$HOMEDIR" ]; then
        continue
    fi

    # 2. 시스템 중요 디렉터리가 홈인 경우 건너뜀 (오탐 및 시스템 보호)
    # 예: root(/), bin(/bin), shutdown(/sbin), nobody(/) 등
    if [[ "$HOMEDIR" == "/" || "$HOMEDIR" == "/bin" || "$HOMEDIR" == "/sbin" || "$HOMEDIR" == "/dev" || "$HOMEDIR" == "/proc" || "$HOMEDIR" == "/sys" ]]; then
        continue
    fi

    # 3. 소유자 및 권한 확인
    # %U: 소유자 이름, %A: 권한 문자열(drwxr-xr-x)
    OWNER=$(stat -c "%U" "$HOMEDIR")
    PERM_STR=$(stat -c "%A" "$HOMEDIR")

    # [진단 1] 소유자 일치 여부 확인
    if [ "$OWNER" != "$USERNAME" ]; then
        U_31_1=1
    fi

    # [진단 2] 타 사용자(Other) 쓰기 권한 확인
    # 권한 문자열의 9번째 문자 (인덱스 8) 확인 (d rwx rwx rwx -> 0 123 456 789)
    # Other Write 비트는 9번째 위치(인덱스 8) 또는 10번째 위치(스티키 비트 고려 시)
    # 간단히 Other 권한(마지막 3자리)에 'w'가 포함되는지 확인
    
    OTHER_PERM=${PERM_STR:7:3} # 마지막 3글자 (Other 권한)
    if [[ "$OTHER_PERM" == *"w"* ]]; then
        U_31_1=1
    fi

done < /etc/passwd

# --- 최종 결과 집계 ---
IS_VUL=$U_31_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-31",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_31_1": $U_31_1
    },
    "timestamp": "$DATE"
  }
}
EOF