#!/bin/bash

# [U-42] 불필요한 RPC 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.96-98
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_42_1 : [inetd] inetd 설정 내 RPC 서비스 활성화 발견
#   U_42_2 : [xinetd] xinetd 설정 내 RPC 서비스 활성화 발견
#   U_42_3 : [systemd/Process] rpcbind 또는 RPC 취약 서비스 활성화 발견

# --- 점검 로직 시작 ---

# 초기화
U_42_1=0
U_42_2=0
U_42_3=0

# 점검 대상 RPC 서비스 목록
RPC_TARGETS=(
    "rpcbind" "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld"
    "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd"
    "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd"
)

# 정규식 생성 (grep -E 용)
RPC_REGEX=$(IFS="|"; echo "${RPC_TARGETS[*]}")

# 1. [systemd/Process] 점검 (U_42_3)
# 오탐 방지를 위해 서비스명/프로세스명 '정확한 일치' 확인

# 1-1. Systemd 서비스 상태 확인
# 활성화된 유닛 목록 가져오기
ACTIVE_UNITS=$(systemctl list-units --type service,socket --no-legend --plain 2>/dev/null | awk '{print $1}')

for target in "${RPC_TARGETS[@]}"; do
    # ^ 와 $ 를 사용하여 정확히 일치하는 서비스/소켓만 찾음 (firewalld vs walld 구분)
    if echo "$ACTIVE_UNITS" | grep -qE "^${target}\.(service|socket)$"; then
        U_42_3=1
        break # 하나라도 발견되면 취약 처리
    fi
done

# 1-2. 프로세스 실행 상태 확인 (Systemd에서 안 잡혔을 경우)
if [[ $U_42_3 -eq 0 ]]; then
    # ps 출력에서 명령어(comm)만 추출하여 정확한 매칭(-xw) 확인
    RUNNING_PROCS=$(ps -e -o comm)
    for target in "${RPC_TARGETS[@]}"; do
        if echo "$RUNNING_PROCS" | grep -xw "$target" >/dev/null; then
            U_42_3=1
            break
        fi
    done
fi

# 2. [xinetd] 점검 (U_42_2)
if [[ -d "/etc/xinetd.d" ]]; then
    # disable = no 설정이 있는지, 그리고 그 서비스가 RPC 목록에 포함되는지 확인
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$RPC_REGEX" | grep -iw "no" >/dev/null 2>&1; then
        U_42_2=1
    fi
fi

# 3. [inetd] 점검 (U_42_1)
if [[ -f "/etc/inetd.conf" ]]; then
    # 주석 제외하고 RPC 서비스 목록 매칭 확인
    if grep -v "^#" /etc/inetd.conf 2>/dev/null | grep -E "$RPC_REGEX" >/dev/null 2>&1; then
        U_42_1=1
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_42_1 -eq 1 ]] || [[ $U_42_2 -eq 1 ]] || [[ $U_42_3 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-42",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_42_1": $U_42_1,
      "U_42_2": $U_42_2,
      "U_42_3": $U_42_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
