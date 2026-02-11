#!/bin/bash

# [U-64] 주기적 보안 패치 및 벤더 권고사항 적용
# 대상 운영체제 : Rocky Linux 9

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-64"
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
U_64_1=0; U_64_2=0; IS_VUL=0

# --- 점검 로직 시작 ---

# 1. 보안 업데이트 확인 (U_64_1)
# dnf check-update --security의 결과 코드가 100이면 업데이트 존재
SEC_RES=$(run_cmd "[U_64_1] 보안 업데이트 대기 목록 확인" "dnf check-update --security -q >/dev/null 2>&1; echo \$?")
if [[ "$SEC_RES" == "100" ]]; then
    U_64_1=1
    log_basis "[U_64_1] 적용 가능한 보안 업데이트가 존재함" "취약"
else
    log_basis "[U_64_1] 보안 업데이트 상태 최신임" "양호"
fi

# 2. 커널 일치 여부 확인 (U_64_2)
CUR_K=$(run_cmd "[U_64_2] 실행 중인 커널 버전 확인" "uname -r")
INS_K=$(run_cmd "[U_64_2] 설치된 최신 커널 버전 확인" "rpm -q kernel --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | sort -V | tail -n 1")

if [[ -n "$INS_K" ]] && [[ "$CUR_K" != "$INS_K" ]]; then
    U_64_2=1
    log_basis "[U_64_2] 최신 커널 설치 후 재부팅되지 않음 (현재: $CUR_K / 최신: $INS_K)" "취약"
else
    log_basis "[U_64_2] 커널 버전 상태 양호" "양호"
fi

if [[ $U_64_1 -eq 1 ]] || [[ $U_64_2 -eq 1 ]]; then IS_VUL=1; fi

cat <<EOF
{
  "meta": { "hostname": "$HOSTNAME", "ip": "$IP", "user": "$USER" },
  "result": {
    "flag_id": "U-64",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "patch",
    "flag": { 
      "U_64_1": $U_64_1,
      "U_64_2": $U_64_2 
    },
    "timestamp": "$DATE"
  }
}
EOF
