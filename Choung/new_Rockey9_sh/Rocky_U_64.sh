#!/bin/bash

# [U-64] 주기적 보안 패치 및 벤더 권고사항 적용
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.160-163
# 자동 조치 가능 유무 : 불가능 (관리자가 직접 dnf update 수행 필요)
# 플래그 설명:
#   U_64_1 : [System] 보안 관련 업데이트(Security) 미적용 상태
#   U_64_2 : [Kernel] 최신 커널 설치 후 재부팅 미실행 (현재 커널 != 최신 커널)

# --- 점검 로직 시작 ---

# 초기화
U_64_1=0
U_64_2=0

# 1. 보안 업데이트 대기 목록 확인 (U_64_1)
# dnf check-update --security
# 리턴코드: 100(업데이트 있음), 0(없음/최신), 1(오류)
# 네트워크 연결이 필요하며, 연결 불가 시 1을 반환하므로 100일 때만 취약 처리
dnf check-update --security -q >/dev/null 2>&1
CHECK_RES=$?

if [[ $CHECK_RES -eq 100 ]]; then
    U_64_1=1
fi

# 2. 커널 버전 일치 여부 확인 (U_64_2)
# 실행 중인 커널 버전
CURRENT_KERNEL=$(uname -r)

# 설치된 커널 중 가장 최신 버전 확인 (RPM 쿼리 및 버전 정렬)
# Rocky Linux 9 기준 kernel 패키지 조회
LATEST_INSTALLED_KERNEL=$(rpm -q kernel --qf "%{VERSION}-%{RELEASE}.%{ARCH}\n" 2>/dev/null | sort -V | tail -n 1)

if [[ -n "$LATEST_INSTALLED_KERNEL" ]]; then
    if [[ "$CURRENT_KERNEL" != "$LATEST_INSTALLED_KERNEL" ]]; then
        # 실행 중인 커널과 설치된 최신 커널이 다르면 재부팅이 필요한 상태로 간주
        U_64_2=1
    fi
fi

# 3. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_64_1 -eq 1 ]] || [[ $U_64_2 -eq 1 ]]; then
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
    "flag_id": "U-64",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "patch",
    "flag": {
      "U_64_1": $U_64_1,
      "U_64_2": $U_64_2
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
