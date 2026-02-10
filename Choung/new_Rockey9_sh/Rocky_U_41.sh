#!/bin/bash

# [U-41] 불필요한 automountd 제거
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.93-95
# 자동 조치 가능 유무 : 가능 (서비스 중지 및 비활성화)
# 플래그 설명:
#   U_41_1 : [Running] automountd(autofs) 서비스 또는 프로세스가 현재 실행 중 (취약)
#   U_41_2 : [Boot] autofs 서비스가 부팅 시 자동 실행되도록 설정됨 (취약)

# --- 점검 로직 시작 ---

# 초기화
U_41_1=0
U_41_2=0

# 1. [Running] 현재 실행 여부 점검 (U_41_1)
# systemd 서비스가 active 상태이거나, 프로세스가 메모리에 떠 있는지 확인 (OR 조건)
SVC_ACTIVE=$(systemctl is-active autofs 2>/dev/null)
PROC_CHECK=$(ps -ef | grep -v grep | grep -E "automount|autofs")

if [[ "$SVC_ACTIVE" == "active" ]] || [[ -n "$PROC_CHECK" ]]; then
    U_41_1=1
fi

# 2. [Boot] 부팅 시 자동 실행 설정 점검 (U_41_2)
# systemctl is-enabled 명령어로 enabled 상태인지 확인
SVC_ENABLED=$(systemctl is-enabled autofs 2>/dev/null)

if [[ "$SVC_ENABLED" == "enabled" ]]; then
    U_41_2=1
fi

# 3. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_41_1 -eq 1 ]] || [[ $U_41_2 -eq 1 ]]; then
    IS_VUL=1
fi

# 4. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-41",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_41_1": $U_41_1,
      "U_41_2": $U_41_2
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
