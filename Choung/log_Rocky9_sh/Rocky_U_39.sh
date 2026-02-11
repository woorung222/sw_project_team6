#!/bin/bash

# [U-39] 불필요한 NFS 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-39"
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
U_39_1=0; U_39_2=0; U_39_3=0; IS_VUL=0

# 1. [U_39_1] systemd 점검
S_RES=$(run_cmd "[U_39_1] nfs-server 서비스 상태 확인" "systemctl is-active nfs-server 2>/dev/null")
if [[ "$S_RES" == "active" ]]; then U_39_1=1; fi
log_basis "[U_39_1] nfs-server 활성화 여부" "$([[ $U_39_1 -eq 1 ]] && echo '취약' || echo '양호')"

# 2. [U_39_2] Process/Net 점검
PORT=$(run_cmd "[U_39_2] NFS/RPC 포트(2049,111) 확인" "ss -tuln 2>/dev/null | awk '{print \$5}' | grep -E ':(2049|111)$'")
PROC=$(run_cmd "[U_39_2] NFS 관련 프로세스 확인" "ps -ef | grep -v grep | grep -E 'nfsd|rpc.nfsd|rpc.mountd'")
if [[ -n "$PORT" ]] || [[ -n "$PROC" ]]; then U_39_2=1; fi
log_basis "[U_39_2] NFS 프로세스/포트 활성 여부" "$([[ $U_39_2 -eq 1 ]] && echo '취약' || echo '양호')"

# 3. [U_39_3] Package/Conf 점검
PKG=$(run_cmd "[U_39_3] NFS 패키지(rpm) 확인" "rpm -qa | grep -E '^nfs-utils|^rpcbind'")
CONF=""
if [[ -f "/etc/exports" ]]; then
    CONF=$(run_cmd "[U_39_3] /etc/exports 공유 설정 확인" "grep -v '^#' /etc/exports 2>/dev/null | grep -v '^$'")
else
    log_step "[U_39_3] 파일 확인" "ls /etc/exports" "파일 없음"
fi
if [[ -n "$PKG" ]] || [[ -n "$CONF" ]]; then U_39_3=1; fi
log_basis "[U_39_3] NFS 패키지/설정 존재 여부" "$([[ $U_39_3 -eq 1 ]] && echo '취약' || echo '양호')"

if [[ $U_39_1 -eq 1 ]] || [[ $U_39_2 -eq 1 ]] || [[ $U_39_3 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_39_1": $U_39_1,
      "U_39_2": $U_39_2,
      "U_39_3": $U_39_3
    },
    "timestamp": "$DATE"
  }
}
EOF
