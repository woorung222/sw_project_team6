#!/bin/bash

# 자동 조치 가능 여부 : 가능 (chmod/chown)
# 점검 내용 : /var/log 내 모든 로그 파일의 소유자 및 권한 전수 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_67_1 : 로그 파일 권한/소유자 위반 여부
U_67_1=0

# --- 3. 점검 로직 수행 ---

LOG_DIR="/var/log"

# [Step 1] find 명령어를 사용하여 /var/log 내의 모든 일반 파일(-type f)을 전수 조사
# 조건 1: 소유자가 root가 아닌 파일 (-not -user root)
# 조건 2: 권한이 644를 초과(Group/Other에 쓰기 권한이 있음)하는 파일 (-perm /022)
# -print -quit : 하나라도 발견되면 즉시 종료하여 성능 최적화

# sudo 권한이 필요할 수 있으므로 sudo 시도 (자동화 환경 고려)
if [ -d "$LOG_DIR" ]; then
    VULN_EXIST=$(sudo find "$LOG_DIR" -type f \( -not -user root -o -perm /022 \) -print -quit 2>/dev/null)

    if [ -n "$VULN_EXIST" ]; then
        U_67_1=1
    fi
else
    # 로그 디렉토리가 없는 경우 (특이 케이스, 일단 양호 처리)
    U_67_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_67_1" -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- 5. JSON 출력 (Stdout) ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP_ADDR",
    "user": "$CURRENT_USER"
  },
  "result": {
    "flag_id": "U-67",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "log",
    "flag": {
      "U_67_1": $U_67_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
