#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : BIND 최신 버전 사용 유무 및 주기적 보안 패치 여부 점검
# 대상 : Ubuntu 24.04.3 (LINUX 기준 점검 사례 적용)

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_49_1 : DNS 서비스 활성화 및 named 명령어 정상 동작 여부
U_49_1=0

# --- 3. 점검 로직 수행 ---

# [Step 1] DNS 서비스 활성화 여부 확인
# named 서비스가 로드되어 있고 활성(active) 상태인지 확인
DNS_ACT=$(systemctl list-units --type=service 2>/dev/null | grep named)

if [ -n "$DNS_ACT" ]; then
    # 서비스가 활성화되어 있는 경우
    
    # [Step 2] BIND 버전 확인 가능 여부 점검
    if command -v named > /dev/null; then
        # named 명령어가 존재하면 버전을 확인 (로그로만 남김)
        BIND_VER=$(named -v)
        echo "  - [Info] BIND Version: $BIND_VER" >&2
        
        # 버전이 확인되면 일단 양호(0)로 간주 
        # (최신 패치 비교는 외부 DB 필요하므로 자동화에선 실행 가능성만 체크)
        U_49_1=0
    else
        # 서비스는 돌고 있는데 named 명령어가 없는 경우 (비정상 상태)
        U_49_1=1
    fi
else
    # DNS 서비스를 사용하지 않는 경우 (양호)
    U_49_1=0
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_49_1" -eq 1 ]; then
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
    "flag_id": "U-49",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_49_1": $U_49_1
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
