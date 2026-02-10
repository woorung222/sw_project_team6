#!/bin/bash

# [U-49] DNS 보안 버전 패치
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.118-120
# 자동 조치 가능 유무 : 수동 조치 (dnf update bind)
# 플래그 설명:
#   U_49_1 : [Service] DNS 서비스(named) 활성화 상태
#   U_49_2 : [Version] 보안 업데이트가 필요한 구버전 발견 (취약)

# --- 점검 로직 시작 ---

# 초기화
U_49_1=0
U_49_2=0

# 1. [Service] DNS 서비스 활성화 확인 (U_49_1)
if systemctl is-active named >/dev/null 2>&1; then
    U_49_1=1

    # 2. [Version] 업데이트 필요 여부 확인 (U_49_2)
    # dnf check-update bind
    # 반환값: 100(업데이트 있음), 0(최신), 1(오류)
    dnf check-update bind -q >/dev/null 2>&1
    CHECK_RES=$?

    if [[ $CHECK_RES -eq 100 ]]; then
        U_49_2=1
    fi
fi

# 3. 전체 취약 여부 판단
# 서비스가 켜져 있어도 최신 버전이면 양호이므로, U_49_2가 1일 때만 취약으로 판단
IS_VUL=0
if [[ $U_49_2 -eq 1 ]]; then
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
    "flag_id": "U-49",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_49_1": $U_49_1,
      "U_49_2": $U_49_2
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
