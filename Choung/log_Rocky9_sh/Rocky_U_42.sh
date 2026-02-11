#!/bin/bash

# [U-42] 불필요한 RPC 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-42"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then
    source "$BASE_DIR/common_logging.sh"
else
    echo "Warning: common_logging.sh not found." >&2
    run_cmd() { eval "$2"; }
    log_step() { :; }
    log_basis() { :; }
fi

# 2. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기화
U_42_1=0; U_42_2=0; U_42_3=0; IS_VUL=0
RPC_TARGETS=("rpcbind" "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld" "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd" "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd")
RPC_REGEX=$(IFS="|"; echo "${RPC_TARGETS[*]}")

# --- 점검 로직 시작 ---

# 1. [U_42_3] systemd/Process 점검
# systemctl 결과를 run_cmd로 남기되, 필터링 과정을 포함하여 로그 양을 조절
ACTIVE_U=$(run_cmd "[U_42_3] 활성 RPC 관련 systemd 유닛 검색" "systemctl list-units --type service,socket --no-legend --plain 2>/dev/null | awk '{print \$1}' | grep -E '^($RPC_REGEX)\.(service|socket)$' || echo '검색 결과 없음'")

if [[ "$ACTIVE_U" != "검색 결과 없음" ]]; then
    U_42_3=1
    log_basis "[U_42_3] systemd 유닛 목록에서 활성 RPC 서비스 발견: $(echo $ACTIVE_U | xargs)" "취약"
else
    log_basis "[U_42_3] systemd 유닛 목록에서 대상 RPC 서비스가 발견되지 않음" "양호"
fi

if [[ $U_42_3 -eq 0 ]]; then
    # [수정 포인트] ps 전체 목록을 찍지 않고, grep으로 대상 서비스만 추출하는 커맨드를 run_cmd로 실행
    # 이렇게 하면 로그에는 전체 프로세스가 아닌 '발견된 서비스' 또는 '없음'만 남습니다.
    FOUND_PROCS=$(run_cmd "[U_42_3] 실행 중인 RPC 프로세스 검색" "ps -e -o comm | grep -xwE '$RPC_REGEX' || echo '검색 결과 없음'")
    
    if [[ "$FOUND_PROCS" != "검색 결과 없음" ]]; then
        U_42_3=1
        log_basis "[U_42_3] 실행 중인 프로세스 목록에서 RPC 서비스 발견: $(echo $FOUND_PROCS | xargs)" "취약"
    else
        log_basis "[U_42_3] 실행 중인 프로세스 목록에서 대상 RPC 서비스가 발견되지 않음" "양호"
    fi
fi
log_basis "[U_42_3] RPC 서비스/프로세스 종합 활성화 여부" "$([[ $U_42_3 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_42_2] xinetd 점검
if [[ -d "/etc/xinetd.d" ]]; then
    X_RES=$(run_cmd "[U_42_2] xinetd 내 RPC 설정(disable=no) 확인" "grep -rEi 'disable' /etc/xinetd.d/ 2>/dev/null | grep -E '$RPC_REGEX' | grep -iw 'no'")
    if [[ -n "$X_RES" ]]; then U_42_2=1; fi
else
    log_step "[U_42_2] 디렉터리 확인" "ls -d /etc/xinetd.d" "디렉터리 없음"
fi
log_basis "[U_42_2] xinetd 내 RPC 서비스 활성화 여부" "$([[ $U_42_2 -eq 1 ]] && echo '취약' || echo '양호')"

# 3. [U_42_1] inetd 점검
if [[ -f "/etc/inetd.conf" ]]; then
    I_RES=$(run_cmd "[U_42_1] inetd 내 RPC 설정 확인" "grep -v '^#' /etc/inetd.conf 2>/dev/null | grep -E '$RPC_REGEX'")
    if [[ -n "$I_RES" ]]; then U_42_1=1; fi
else
    log_step "[U_42_1] 파일 확인" "ls /etc/inetd.conf" "파일 없음"
fi
log_basis "[U_42_1] inetd 내 RPC 서비스 활성화 여부" "$([[ $U_42_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 최종 취약 여부 판단
if [[ $U_42_1 -eq 1 ]] || [[ $U_42_2 -eq 1 ]] || [[ $U_42_3 -eq 1 ]]; then IS_VUL=1; fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_42_1": $U_42_1,
      "U_42_2": $U_42_2,
      "U_42_3": $U_42_3
    },
    "timestamp": "$DATE"
  }
}
EOF