#!/bin/bash

# 자동 조치 가능 여부 : 가능
# 점검 내용 : NFS 서비스 활성화 여부 확인 및 불필요한 서비스 비활성화 점검
# 대상 : Ubuntu 24.04.3

# --- 1. 메타데이터 수집 ---
HOSTNAME=$(hostname)
IP_ADDR=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
TIMESTAMP=$(date "+%Y_%m_%d / %H:%M:%S")

# --- 2. 점검 변수 초기화 ---
# U_39_1 : [가이드 필수] systemctl list-units 명령어를 통한 nfs 서비스 활성 여부
# U_39_2 : [프로세스/포트] nfsd 프로세스 및 2049/111 포트 오픈 여부
# U_39_3 : [패키지/설정] nfs 패키지 설치 및 /etc/exports 설정 존재 여부
U_39_1=0
U_39_2=0
U_39_3=0

# --- 3. 점검 로직 수행 ---

# [Step 1] 가이드 명시 필수 점검 (Systemd Service)
# 활성화(running/active)된 nfs 관련 서비스 유닛 확인
NFS_SERVICE_UNIT=$(systemctl list-units --type=service | grep nfs)

if [ -n "$NFS_SERVICE_UNIT" ]; then
    U_39_1=1
fi

# [Step 2] 실행 중인 프로세스 및 포트 점검
# 포트: 2049(NFS), 111(RPC)
# 프로세스: nfsd, mountd
NFS_PORT=$(sudo netstat -antup 2>/dev/null | grep -E ":(2049|111) " | grep "LISTEN")
NFS_PROC=$(ps -ef | grep -E "nfsd|mountd" | grep -v "grep")

if [ -n "$NFS_PORT" ] || [ -n "$NFS_PROC" ]; then
    U_39_2=1
fi

# [Step 3] 관련 패키지 및 설정 파일 점검
# 패키지: nfs-kernel-server, rpcbind
# 설정: /etc/exports 내에 주석이 아닌 활성 라인이 있는지 확인
NFS_PKG=$(dpkg -l | grep -E "nfs-kernel-server|rpcbind" | grep "^ii")
EXPORT_CONF=""
if [ -f "/etc/exports" ]; then
    EXPORT_CONF=$(sudo grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$")
fi

if [ -n "$NFS_PKG" ] || [ -n "$EXPORT_CONF" ]; then
    U_39_3=1
fi

# --- 4. 최종 취약 여부 판단 ---
if [ "$U_39_1" -eq 1 ] || [ "$U_39_2" -eq 1 ] || [ "$U_39_3" -eq 1 ]; then
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
    "flag_id": "U-39",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_39_1": $U_39_1,
      "U_39_2": $U_39_2,
      "U_39_3": $U_39_3
    },
    "timestamp": "$TIMESTAMP"
  }
}
EOF
