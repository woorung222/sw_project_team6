#!/bin/bash

# [U-07] 불필요한 계정 제거
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : 불필요한 계정(기본 미사용 계정, 장기 미사용 계정)이 존재하지 않는 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_07_1=0 # [파일 점검] 불필요한 기본 계정 존재 여부
U_07_2=0 # [로그 점검] 장기 미사용 계정 존재 여부
IS_VUL=0 # 전체 취약 여부

# --- [U_07_1] /etc/passwd 파일을 이용하여 점검 ---
# 기준: lp, uucp, games, gopher 등 시스템에 불필요한 기본 계정이 존재하는지 확인

# 점검할 불필요 계정 목록
UNNECESSARY_ACCOUNTS=("lp" "uucp" "games" "gopher" "ftp" "news")
DETECTED_ACCOUNTS=()

for ACCT in "${UNNECESSARY_ACCOUNTS[@]}"; do
    # /etc/passwd에 해당 계정이 존재하는지 확인
    if grep -q "^$ACCT:" /etc/passwd; then
        DETECTED_ACCOUNTS+=("$ACCT")
    fi
done

if [ ${#DETECTED_ACCOUNTS[@]} -gt 0 ]; then
    # 불필요한 계정이 하나라도 발견되면 취약
    U_07_1=1
else
    U_07_1=0
fi

# --- [U_07_2] log를 이용하여 점검 ---
# 기준: 사용자 계정(UID >= 1000) 중 장기간(예: 90일) 로그인 기록이 없는 계정 확인
# 가이드에는 'last' 명령어를 언급했으나, 자동화 진단에서는 'lastlog'가 더 정확하므로 이를 활용하여 구현
# (last는 로그 로테이션으로 인해 오래된 기록이 사라질 수 있음)

IDLE_LIMIT_DAYS=90
LONG_IDLE_FOUND=0
CURRENT_EPOCH=$(date +%s)

# /etc/passwd에서 UID 1000 이상인 일반 사용자 추출
while IFS=: read -r username _ uid _ _ _ _; do
    if [ "$uid" -ge 1000 ] && [ "$username" != "nobody" ]; then
        # lastlog 명령어로 마지막 접속일 확인
        # lastlog 출력 예: "username         pts/0    192.168.1.1   Wed Feb  9 12:00:00 +0900 2026"
        # "Never logged in"인 경우도 포함하여 점검
        
        LAST_LOGIN_INFO=$(lastlog -u "$username" | tail -n 1)
        
        if [[ "$LAST_LOGIN_INFO" == *"Never logged in"* ]]; then
             # 한번도 로그인하지 않은 계정도 불필요한 계정으로 간주 (정책에 따라 다를 수 있음)
             LONG_IDLE_FOUND=1
        else
             # 날짜 추출 및 계산 (시스템 환경에 따라 날짜 형식이 다를 수 있어 간단한 체크 로직 적용)
             # 여기서는 lastlog의 'days' 옵션을 활용하여 직접 필터링하는 방식이 더 안정적임
             :
        fi
    fi
done < /etc/passwd

# 위의 파싱 방식보다 lastlog -b (before) 옵션을 사용하는 것이 정확함
# lastlog -b 90 : 90일 이상 로그인하지 않은 계정 출력
# 단, 시스템 계정(UID < 1000)은 제외해야 하므로 교차 검증 필요

CHECK_IDLE=$(lastlog -b $IDLE_LIMIT_DAYS 2>/dev/null | awk '{print $1}' | tail -n +2)
if [ ! -z "$CHECK_IDLE" ]; then
    # 90일 이상 미접속 계정이 존재함 -> 이 중 UID 1000 이상인 계정이 있는지 확인
    for usr in $CHECK_IDLE; do
        chk_uid=$(id -u "$usr" 2>/dev/null)
        if [ ! -z "$chk_uid" ] && [ "$chk_uid" -ge 1000 ] && [ "$usr" != "nobody" ]; then
            LONG_IDLE_FOUND=1
            break
        fi
    done
fi

if [ $LONG_IDLE_FOUND -eq 1 ]; then
    U_07_2=1
else
    U_07_2=0
fi

# --- 전체 결과 집계 ---
if [ $U_07_1 -eq 1 ] || [ $U_07_2 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-07",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_07_1": $U_07_1,
      "U_07_2": $U_07_2
    },
    "timestamp": "$DATE"
  }
}
EOF