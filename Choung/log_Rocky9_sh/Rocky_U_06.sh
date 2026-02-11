#!/bin/bash

# [U-06] 사용자 계정 su 기능 제한
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : su 명령어를 특정 그룹(wheel)에 속한 사용자만 사용하도록 제한된 경우 양호

set -u

# 1. Flag ID 설정 및 공통 로깅 모듈 로드
FLAG_ID="U-06"
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

# 초기 상태 설정
U_06_1=0 # 파일 권한/그룹 점검
U_06_2=0 # PAM 설정 점검
IS_VUL=0

# --- 점검 로직 시작 ---

# ---------------------------------------------------------
# 1. [U_06_1] su 실행 파일 권한 및 그룹 점검
# ---------------------------------------------------------
SU_BIN="/usr/bin/su"

if [ -f "$SU_BIN" ]; then
    # 1. 그룹 확인 (wheel 그룹인지)
    SU_GROUP=$(run_cmd "[U_06_1] su 파일 소유 그룹 확인" "stat -c '%G' $SU_BIN")
    
    # 2. 권한 확인 (4750 이하인지)
    SU_PERM=$(run_cmd "[U_06_1] su 파일 권한(Octal) 확인" "stat -c '%a' $SU_BIN")

    # 진단 로직: 그룹이 wheel이고, 권한이 4750 이하(Other 실행 불가)여야 함
    if [ "$SU_GROUP" != "wheel" ]; then
        U_06_1=1
        log_basis "[U_06_1] su 파일 그룹이 wheel이 아님 (현재: $SU_GROUP)" "취약"
    elif [ "$SU_PERM" -gt 4750 ]; then
        U_06_1=1
        log_basis "[U_06_1] su 파일 권한이 4750보다 취약함 (현재: $SU_PERM, Other 실행 가능)" "취약"
    else
        U_06_1=0
        log_basis "[U_06_1] su 파일 그룹(wheel) 및 권한($SU_PERM)이 적절함" "양호"
    fi
else
    # 파일이 없는 경우 (매우 이례적이나 취약 처리)
    U_06_1=1
    log_step "[U_06_1] su 파일 존재 여부" "[ -f $SU_BIN ]" "파일 없음"
    log_basis "[U_06_1] /usr/bin/su 파일이 존재하지 않음" "취약"
fi

# ---------------------------------------------------------
# 2. [U_06_2] PAM 설정 점검 (pam_wheel.so)
# ---------------------------------------------------------
PAM_SU="/etc/pam.d/su"

if [ -f "$PAM_SU" ]; then
    # 주석(#) 제외하고 auth required pam_wheel.so 설정 확인
    CMD="grep -v '^#' $PAM_SU | grep 'auth' | grep 'required' | grep 'pam_wheel.so'"
    PAM_CHECK=$(run_cmd "[U_06_2] PAM 설정(pam_wheel.so) 확인" "$CMD")
    
    if [ -z "$PAM_CHECK" ]; then
        # 설정이 없거나 주석 처리되어 있으면 취약
        U_06_2=1
        log_basis "[U_06_2] /etc/pam.d/su 파일에 pam_wheel.so 모듈 설정이 없음" "취약"
    else
        U_06_2=0
        log_basis "[U_06_2] PAM 설정에 pam_wheel.so 모듈이 적용됨" "양호"
    fi
else
    # PAM 설정 파일이 없으면 취약
    U_06_2=1
    log_step "[U_06_2] PAM 설정 파일 존재 여부" "[ -f $PAM_SU ]" "파일 없음"
    log_basis "[U_06_2] /etc/pam.d/su 파일이 존재하지 않음" "취약"
fi

# ---------------------------------------------------------
# 3. 전체 결과 집계
# ---------------------------------------------------------
# 하나라도 취약하면 전체 취약
if [ $U_06_1 -eq 1 ] || [ $U_06_2 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# ---------------------------------------------------------
# 4. JSON 출력 (stdout)
# ---------------------------------------------------------
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
    "is_auto": 1,
    "category": "account",
    "flag": {
      "U_06_1": $U_06_1,
      "U_06_2": $U_06_2
    },
    "timestamp": "$DATE"
  }
}
EOF
