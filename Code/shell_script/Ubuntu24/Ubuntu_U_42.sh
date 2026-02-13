#!/usr/bin/env bash
set -u

# =========================================================
# U_42 (상) 불필요한 RPC 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준: 가이드에 명시된 불필요한 RPC 서비스 16종 활성화 여부 점검
# - Rocky 논리 반영:
#   U_42_1 : [inetd] 내 RPC 서비스 설정 여부
#   U_42_2 : [xinetd] 내 RPC 서비스 설정 여부
#   U_42_3 : [systemd/Process] rpcbind 및 RPC 취약 서비스 활성 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_42"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
U_42_1=0
U_42_2=0
U_42_3=0

# 점검 대상 RPC 서비스 리스트 (Rocky/Ansible 16종 기준 통일)
RPC_TARGETS=(
    "rpcbind" "rpc.cmsd" "rpc.ttdbserverd" "sadmind" "rusersd" "walld"
    "sprayd" "rstatd" "rpc.nisd" "rexd" "rpc.pcnfsd"
    "rpc.statd" "rpc.ypupdated" "rpc.rquotad" "kcms_server" "cachefsd"
)
RPC_REGEX=$(IFS="|"; echo "${RPC_TARGETS[*]}")

# -------------------------
# 1. [inetd] 점검 (U_42_1)
# -------------------------
if [ -f "/etc/inetd.conf" ]; then
    if grep -v "^#" /etc/inetd.conf | grep -E "($RPC_REGEX)" >/dev/null 2>&1; then
        U_42_1=1
    fi
fi

# -------------------------
# 2. [xinetd] 점검 (U_42_2)
# -------------------------
if [ -d "/etc/xinetd.d" ]; then
    if grep -rEi "disable" /etc/xinetd.d/ 2>/dev/null | grep -E "($RPC_REGEX)" | grep -iw "no" >/dev/null 2>&1; then
        U_42_2=1
    fi
fi

# -------------------------
# 3. [systemd/rpcinfo] 점검 (U_42_3)
# -------------------------
# 3-1. systemd Active 상태 확인
for svc in "${RPC_TARGETS[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        U_42_3=1
        break
    fi
done

# 3-2. rpcinfo를 통한 실시간 등록 서비스 확인 (보조 점검)
if [ "$U_42_3" -eq 0 ] && command -v rpcinfo >/dev/null; then
    if rpcinfo -p 2>/dev/null | grep -E "($RPC_REGEX)" >/dev/null 2>&1; then
        U_42_3=1
    fi
fi

# -------------------------
# VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$U_42_1" -eq 1 ] || [ "$U_42_2" -eq 1 ] || [ "$U_42_3" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# Output (JSON)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_42_1": $U_42_1,
      "U_42_2": $U_42_2,
      "U_42_3": $U_42_3
    },
    "timestamp": "$DATE"
  }
}
EOF