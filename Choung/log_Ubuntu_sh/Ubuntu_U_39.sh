#!/bin/bash

# [U-39] NFS 서비스 활성화 여부 확인 및 불필요한 서비스 비활성화 점검
# 대상 운영체제 : Ubuntu 24.04

set -u

FLAG_ID="U-39"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$BASE_DIR/common_logging.sh" ]; then source "$BASE_DIR/common_logging.sh"; fi

HOSTNAME=$(hostname); IP=$(hostname -I | awk '{print $1}'); USER=$(whoami); DATE=$(date "+%Y_%m_%d / %H:%M:%S")

U_39_1=0; U_39_2=0; U_39_3=0; IS_VUL=0

# 1. [U_39_1] systemd 서비스 점검
NFS_SVC=$(run_cmd "[U_39_1] NFS 서비스 유닛 확인" "systemctl list-units --type=service | grep nfs || echo 'none'")
if [[ "$NFS_SVC" != "none" ]]; then
    U_39_1=1
    log_basis "[U_39_1] NFS 서비스가 활성화되어 있음" "취약"
else
    log_basis "[U_39_1] NFS 서비스 비활성" "양호"
fi

# 2. [U_39_2] 프로세스 및 포트 점검
NFS_PORT=$(run_cmd "[U_39_2] NFS 관련 포트(2049, 111) 확인" "netstat -antup 2>/dev/null | grep -E ':(2049|111) ' | grep 'LISTEN' || echo 'none'")
NFS_PROC=$(run_cmd "[U_39_2] NFS 관련 프로세스(nfsd, mountd) 확인" "ps -ef | grep -E 'nfsd|mountd' | grep -v 'grep' || echo 'none'")

if [[ "$NFS_PORT" != "none" ]] || [[ "$NFS_PROC" != "none" ]]; then
    U_39_2=1
    log_basis "[U_39_2] NFS 관련 포트 또는 프로세스 발견" "취약"
else
    log_basis "[U_39_2] NFS 관련 포트/프로세스 미발견" "양호"
fi

# 3. [U_39_3] 패키지 및 설정 파일 점검
NFS_PKG=$(run_cmd "[U_39_3] NFS 패키지 설치 확인" "dpkg -l | grep -E 'nfs-kernel-server|rpcbind' | grep '^ii' || echo 'none'")
EXP_CONF=$(run_cmd "[U_39_3] /etc/exports 활성 설정 확인" "grep -v '^#' /etc/exports 2>/dev/null | grep -v '^$' || echo 'none'")

if [[ "$NFS_PKG" != "none" ]] || [[ "$EXP_CONF" != "none" ]]; then
    U_39_3=1
    log_basis "[U_39_3] NFS 패키지 설치됨 또는 exports 설정 존재" "취약"
else
    log_basis "[U_39_3] NFS 패키지 미설치 및 설정 없음" "양호"
fi

if [[ $U_39_1 -eq 1 || $U_39_2 -eq 1 || $U_39_3 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-39",
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
