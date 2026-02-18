#!/bin/bash

# [U-43] NIS 서비스 비활성화
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.99-101
# 자동 조치 가능 유무 : 가능
# 플래그 설명:
#   U_43_1 : [systemd/Process] NIS 서비스(ypserv, ypbind 등) 활성화 발견

# --- 점검 로직 시작 ---

# 초기화
U_43_1=0

# 점검 대상 NIS 서비스 목록
# ypserv: NIS 서버, ypbind: NIS 클라이언트
NIS_TARGETS=("ypserv" "ypbind" "ypxfrd" "rpc.yppasswdd" "rpc.ypupdated")

# 정규식 생성 (grep -E 용)
NIS_REGEX=$(IFS="|"; echo "${NIS_TARGETS[*]}")

# 1. [systemd] 점검 (U_43_1)
# Systemd 유닛 활성화 여부 확인
if systemctl list-units --type service,socket 2>/dev/null | grep -E "$NIS_REGEX" | grep -w "active" >/dev/null 2>&1; then
    U_43_1=1
fi

# 2. [Process] 점검 (U_43_1)
# 프로세스 실행 여부 확인 (Systemd에서 안 잡혔을 경우 재확인)
if [[ $U_43_1 -eq 0 ]]; then
    for svc in "${NIS_TARGETS[@]}"; do
        if ps -e -o comm | grep -xw "$svc" >/dev/null 2>&1; then
            U_43_1=1
            break
        fi
    done
fi

# 3. 전체 취약 여부 판단
IS_VUL=$U_43_1

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-43",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_43_1": $U_43_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
