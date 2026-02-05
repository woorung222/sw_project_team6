#!/bin/bash

# [U-42] 불필요한 RPC 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.96-98
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_42_1 : [systemd/Process] rpcbind 또는 RPC 취약 서비스 활성화 발견
#   U_42_2 : [xinetd] xinetd 설정 내 RPC 서비스 활성화 발견
#   U_42_3 : [inetd] inetd 설정 내 RPC 서비스 활성화 발견

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "----------------------------------------------------------------"
echo "[U-42] 불필요한 RPC 서비스 비활성화 점검 시작"
echo "----------------------------------------------------------------"

VULN_STATUS=0
VULN_FLAGS=()

# 점검 대상 RPC 서비스 목록
RPC_TARGETS=(
    "rpcbind" "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld"
    "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd"
    "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd"
)

# 정규식 생성 (grep -E 용)
RPC_REGEX=$(IFS="|"; echo "${RPC_TARGETS[*]}")

# 1. [systemd/Process] 점검 (U_42_1) - PDF p.97
# [오탐 방지 수정] grep -w 옵션을 사용하여 'walld'가 'firewalld'에 매칭되지 않도록 함
# 1차 필터링 후, awk 등으로 서비스명을 정확히 파싱하거나 grep -w로 재검증
SYS_CHECK_RAW=$(systemctl list-units --type service,socket 2>/dev/null | grep -E "$RPC_REGEX" | grep -w "active")

SYS_CHECK_FINAL=""
if [[ -n "$SYS_CHECK_RAW" ]]; then
    # 한 줄씩 읽어서 서비스 이름이 정확히 일치하는지 확인 (예: walld.service vs firewalld.service)
    while read -r line; do
        for target in "${RPC_TARGETS[@]}"; do
            # 서비스 이름이 "target.service" 또는 "target.socket" 형태인지 정확히 확인
            # 단어 경계(\b)를 사용하여 firewalld가 walld에 걸리지 않게 함
            if echo "$line" | grep -qE "\b$target\.(service|socket)\b"; then
                SYS_CHECK_FINAL="$SYS_CHECK_FINAL $target"
            fi
        done
    done <<< "$SYS_CHECK_RAW"
fi

# 프로세스 점검 (이미 -xw 사용 중이라 안전하지만 재확인)
PROC_CHECK=""
for svc in "${RPC_TARGETS[@]}"; do
    if ps -e -o comm | grep -xw "$svc" >/dev/null; then
        PROC_CHECK="$PROC_CHECK $svc"
    fi
done

if [[ -n "$SYS_CHECK_FINAL" ]] || [[ -n "$PROC_CHECK" ]]; then
    VULN_STATUS=1
    VULN_FLAGS+=("U_42_1")
    echo -e "${RED}[취약]${NC} [systemd/Process] 불필요한 RPC 서비스가 활성화되어 있습니다."
    [[ -n "$SYS_CHECK_FINAL" ]] && echo "   -> Systemd 활성화: $SYS_CHECK_FINAL"
    [[ -n "$PROC_CHECK" ]] && echo "   -> Process 실행중: $PROC_CHECK"
fi

# 2. [xinetd] 점검 (U_42_2) - PDF p.97
if [[ -d "/etc/xinetd.d" ]]; then
    XINETD_CHECK=$(grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "$RPC_REGEX" | grep -iw "no")
    if [[ -n "$XINETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_42_2")
        echo -e "${RED}[취약]${NC} [xinetd] 설정에서 RPC 서비스가 활성화되어 있습니다."
    fi
fi

# 3. [inetd] 점검 (U_42_3) - PDF p.96
if [[ -f "/etc/inetd.conf" ]]; then
    INETD_CHECK=$(grep -v "^#" /etc/inetd.conf | grep -E "$RPC_REGEX")
    if [[ -n "$INETD_CHECK" ]]; then
        VULN_STATUS=1
        VULN_FLAGS+=("U_42_3")
        echo -e "${RED}[취약]${NC} [inetd] 설정에서 RPC 서비스가 활성화되어 있습니다."
    fi
fi

# 최종 결과 출력
echo "----------------------------------------------------------------"
if [[ $VULN_STATUS -eq 0 ]]; then
    echo -e "${GREEN}[양호]${NC} rpcbind 및 불필요한 RPC 서비스가 비활성화되어 있습니다."
else
    echo -e "결과: ${RED}[취약]${NC}"
fi

# 디버그 플래그 출력
if [[ ${#VULN_FLAGS[@]} -eq 0 ]]; then
    echo "Debug: Activated flag : {NULL}"
else
    UNIQUE_FLAGS=($(echo "${VULN_FLAGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    FLAGS_STR=$(printf ",%s" "${UNIQUE_FLAGS[@]}")
    echo "Debug: Activated flag : {${FLAGS_STR:1}}"
fi
echo "----------------------------------------------------------------"
