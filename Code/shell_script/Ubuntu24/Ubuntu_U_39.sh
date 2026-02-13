#!/usr/bin/env bash
set -u

# =========================================================
# U_39 (상) 불필요한 NFS 서비스 비활성화 | Ubuntu 24.04
# - 진단 기준: NFS 서비스(nfs-server, rpcbind) 활성화 여부 점검
# - Rocky 논리 반영:
#   U_39_1 : systemd 서비스(nfs-server, rpcbind) Active 여부
#   U_39_2 : NFS 관련 프로세스 및 포트(2049, 111) Listen 여부
#   U_39_3 : NFS 패키지 설치 또는 /etc/exports 설정 존재 여부
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_39"
CATEGORY="service"
IS_AUTO=1

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
U_39_1=0
U_39_2=0
U_39_3=0

# -------------------------
# 1. [systemd] 점검 (U_39_1)
# -------------------------
# nfs-server 또는 rpcbind가 하나라도 Active이면 취약
if systemctl is-active --quiet nfs-server 2>/dev/null || \
   systemctl is-active --quiet rpcbind 2>/dev/null; then
    U_39_1=1
fi

# -------------------------
# 2. [Process/Net] 점검 (U_39_2)
# -------------------------
# 2-1. 포트 확인 (NFS: 2049, RPC: 111) - ss 명령어 사용 권장
PORT_CHECK=$(ss -tuln 2>/dev/null | grep -E ":(2049|111)\s")

# 2-2. 프로세스 확인 (nfsd, mountd)
PROC_CHECK=$(ps -ef | grep -v grep | grep -E "nfsd|mountd")

if [ -n "$PORT_CHECK" ] || [ -n "$PROC_CHECK" ]; then
    U_39_2=1
fi

# -------------------------
# 3. [Package/Conf] 점검 (U_39_3)
# -------------------------
# 3-1. 패키지 확인 (Ubuntu 기준: nfs-kernel-server, nfs-common, rpcbind)
PACKAGES="nfs-kernel-server nfs-common rpcbind"
INSTALLED_PKG=$(dpkg -l $PACKAGES 2>/dev/null | grep "^ii")

# 3-2. 설정 파일 확인 (/etc/exports)
CONF_CHECK=""
if [ -f "/etc/exports" ]; then
    # 주석을 제외한 설정 라인이 있는지 확인
    CONF_CHECK=$(grep -v "^#" /etc/exports | grep -v "^$")
fi

if [ -n "$INSTALLED_PKG" ] || [ -n "$CONF_CHECK" ]; then
    U_39_3=1
fi

# -------------------------
# VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$U_39_1" -eq 1 ] || [ "$U_39_2" -eq 1 ] || [ "$U_39_3" -eq 1 ]; then
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
      "U_39_1": $U_39_1,
      "U_39_2": $U_39_2,
      "U_39_3": $U_39_3
    },
    "timestamp": "$DATE"
  }
}
EOF