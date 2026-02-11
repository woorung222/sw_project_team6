#!/bin/bash

# [U-64] OS 버전 EOL 여부 및 커널 보안 패치 상태 점검
# 대상 : Ubuntu 24.04

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

# --- 점검 로직 수행 ---

# 1. [U_64_1] 보안 관련 업데이트 점검
# 중요: 결과가 없으면 빈 문자열이 반환됨. 따라서 결과가 '있으면' 취약으로 판단.
CMD_UPDATE="apt-get -s dist-upgrade 2>/dev/null | grep -i '^Inst' | grep -i 'security' | head -n 5"
SEC_UPDATE_CHECK=$(run_cmd "[U_64_1] 보안 업데이트 시뮬레이션" "$CMD_UPDATE")

if [[ -n "$SEC_UPDATE_CHECK" ]]; then
    U_64_1=1
    log_basis "[U_64_1] 보안 업데이트 필요 패키지 발견: $SEC_UPDATE_CHECK (외 다수)" "취약"
else
    # 업데이트 내역이 없어서 출력이 비어있는 경우 -> 양호
    log_basis "[U_64_1] 대기 중인 보안 업데이트 없음 (최신 상태)" "양호"
fi

# 2. [U_64_2] 커널 버전 불일치(재부팅 필요) 점검
# 현재 커널
CUR_KERNEL=$(run_cmd "[U_64_2] 현재 커널 버전" "uname -r")

# 설치된 최신 커널 (dpkg)
LATEST_KERNEL=$(run_cmd "[U_64_2] 설치된 최신 커널 확인" "dpkg -l | grep 'linux-image-[0-9]' | grep '^ii' | awk '{print \$2}' | sort -V | tail -n 1 || echo 'none'")

if [[ "$LATEST_KERNEL" != "none" ]]; then
    # 문자열 포함 여부 체크 (최신 패키지명에 현재 버전이 포함되는지)
    if [[ "$LATEST_KERNEL" != *"$CUR_KERNEL"* ]]; then
        U_64_2=1
        log_basis "[U_64_2] 현재 커널($CUR_KERNEL)이 설치된 최신 커널($LATEST_KERNEL)과 다름 (재부팅 필요)" "취약"
    else
        # reboot-required 파일 확인 (이중 점검)
        REBOOT_FILE_CHECK=$(run_cmd "[U_64_2] reboot-required 파일 확인" "ls /var/run/reboot-required 2>/dev/null || echo 'none'")
        
        if [[ "$REBOOT_FILE_CHECK" != "none" ]]; then
            # 파일이 있으면 내용 확인
            REBOOT_PKGS=$(run_cmd "[U_64_2] 재부팅 필요 패키지 확인" "grep 'linux-image' /var/run/reboot-required.pkgs 2>/dev/null || echo 'none'")
            if [[ "$REBOOT_PKGS" != "none" ]]; then
                U_64_2=1
                log_basis "[U_64_2] 시스템 재부팅 필요 파일 존재 (/var/run/reboot-required)" "취약"
            else
                log_basis "[U_64_2] 커널 버전 일치 및 재부팅 필요사항 없음" "양호"
            fi
        else
            log_basis "[U_64_2] 커널 버전 일치 ($CUR_KERNEL)" "양호"
        fi
    fi
else
    # dpkg 조회 실패 시
    U_64_2=0 
    log_basis "[U_64_2] 설치된 커널 패키지 목록을 확인할 수 없음 (판단 불가)" "정보"
fi

# 최종 취약 여부 판단
if [[ $U_64_1 -eq 1 || $U_64_2 -eq 1 ]]; then
    IS_VUL=1
fi

# JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
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