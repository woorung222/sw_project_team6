#!/bin/bash

# [U-39] 불필요한 NFS 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.86-88
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_39_1 : [systemd] nfs-server 서비스 활성화 발견
#   U_39_2 : [Process/Net] NFS 관련 프로세스 실행 또는 포트(2049, 111) Listen 발견
#   U_39_3 : [Package/Conf] NFS 패키지 설치 또는 /etc/exports 공유 설정 발견

# --- 점검 로직 시작 ---

# 초기화
U_39_1=0
U_39_2=0
U_39_3=0

# 1. [systemd] 점검 (U_39_1)
# nfs-server 서비스 활성화 여부 확인
if systemctl is-active nfs-server 2>/dev/null | grep -w "active" >/dev/null 2>&1; then
    U_39_1=1
fi

# 2. [Process/Net] 점검 (U_39_2)
# 2-1. 포트 확인 (NFS: 2049, RPC: 111)
# Rocky Linux 9에는 netstat 대신 ss가 기본일 수 있어 ss 사용 (호환성 고려)
PORT_CHECK=$(ss -tuln 2>/dev/null | awk '{print $5}' | grep -E ":(2049|111)$")

# 2-2. 프로세스 확인 (nfsd, rpc.nfsd, rpc.mountd)
PROC_CHECK=$(ps -ef | grep -v grep | grep -E "nfsd|rpc.nfsd|rpc.mountd")

if [[ -n "$PORT_CHECK" ]] || [[ -n "$PROC_CHECK" ]]; then
    U_39_2=1
fi

# 3. [Package/Conf] 점검 (U_39_3)
# 3-1. 패키지 확인 (Rocky Linux는 rpm 사용)
# nfs-utils (NFS 서버), rpcbind (RPC 매퍼)
PKG_CHECK=$(rpm -qa 2>/dev/null | grep -E "^nfs-utils|^rpcbind")

# 3-2. 설정 파일 확인 (/etc/exports)
CONF_CHECK=""
if [[ -f "/etc/exports" ]]; then
    # 주석(#) 제외, 빈 줄 제외하고 내용이 있는지 확인
    CONF_CHECK=$(grep -v "^#" /etc/exports 2>/dev/null | grep -v "^$")
fi

if [[ -n "$PKG_CHECK" ]] || [[ -n "$CONF_CHECK" ]]; then
    U_39_3=1
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_39_1 -eq 1 ]] || [[ $U_39_2 -eq 1 ]] || [[ $U_39_3 -eq 1 ]]; then
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
    "flag_id": "U-39",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flags": {
      "U_39_1": $U_39_1,
      "U_39_2": $U_39_2,
      "U_39_3": $U_39_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
