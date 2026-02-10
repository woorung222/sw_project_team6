#!/bin/bash

# [U-06] 사용자 계정 su 기능 제한
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우 양호

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_06_1=0 # [PAM 미사용 시] 파일 권한 및 그룹 점검
U_06_2=0 # [PAM 사용 시] PAM 설정 점검
IS_VUL=0 # 전체 취약 여부

# --- [U_06_1] PAM 모듈 이용 중이지 않을 경우 (파일 권한 점검) ---
# 기준: /usr/bin/su 파일의 그룹이 wheel이고, 권한이 4750 이하인지 확인

SU_BIN="/usr/bin/su"

if [ -f "$SU_BIN" ]; then
    # 그룹 확인 (wheel 그룹인지)
    SU_GROUP=$(stat -c "%G" "$SU_BIN")
    # 권한 확인 (숫자형)
    SU_PERM=$(stat -c "%a" "$SU_BIN")

    # 그룹이 wheel이 아니거나, 권한이 4750보다 루즈한 경우(예: 4755) 취약
    # 4750 권한은 SUID(4) + User(7) + Group(5) + Other(0) 입니다.
    # Other에 실행 권한이 있거나(5), Group이 wheel이 아니면 취약으로 판단
    
    if [ "$SU_GROUP" != "wheel" ] || [ "$SU_PERM" -gt 4750 ]; then
        U_06_1=1
    else
        U_06_1=0
    fi
else
    # 파일이 없으면 점검 불가(혹은 비정상) -> 편의상 취약 처리 또는 0(사용안함) 처리
    # 여기서는 su가 없을 수 없으므로 1로 처리
    U_06_1=1
fi

# --- [U_06_2] PAM 모듈 이용 중인 경우 (PAM 설정 점검) ---
# 기준: /etc/pam.d/su 파일에서 pam_wheel.so 모듈 활성화 여부 확인

PAM_SU="/etc/pam.d/su"

if [ -f "$PAM_SU" ]; then
    # 주석(#) 제외하고 auth required pam_wheel.so 설정이 있는지 확인
    # use_uid 또는 group=wheel 옵션이 있는지 확인
    PAM_CHECK=$(grep -v "^#" "$PAM_SU" | grep "auth" | grep "required" | grep "pam_wheel.so")
    
    if [ -z "$PAM_CHECK" ]; then
        # 설정이 없거나 주석 처리되어 있으면 취약
        U_06_2=1
    else
        U_06_2=0
    fi
else
    # PAM 설정 파일이 없으면 취약
    U_06_2=1
fi

# --- 전체 결과 집계 ---
# 가이드라인: U-xx-n 중 하나라도 취약점이 있으면 1
if [ $U_06_1 -eq 1 ] || [ $U_06_2 -eq 1 ]; then
    IS_VUL=1
else
    IS_VUL=0
fi

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-06",
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