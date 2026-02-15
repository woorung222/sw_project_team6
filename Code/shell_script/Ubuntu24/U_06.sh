#!/usr/bin/env bash
set -u

# =========================================================
# U_06 (상) 사용자 계정 su 기능 제한 | Ubuntu 24.04
# - 진단 기준: su 명령어를 특정 그룹(wheel)만 사용 가능하도록 제한
# - Rocky 논리 반영:
#   U_06_1: /usr/bin/su 파일 권한(4750) 및 그룹(wheel) 점검
#   U_06_2: /etc/pam.d/su 내 pam_wheel.so 설정 점검
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_06"
CATEGORY="account"
IS_AUTO=1  # Rocky/Ansible 기준에 따라 자동 가능으로 설정

# -------------------------
# Flags (0: 양호, 1: 취약)
# -------------------------
FLAG_U_06_1=0
FLAG_U_06_2=0

# -------------------------
# 1) [U_06_1] 파일 권한 및 그룹 점검
# - 대상: /usr/bin/su (Ubuntu는 /usr/bin/su가 원본)
# - 기준: 그룹 wheel, 권한 4750 이하
# -------------------------
SU_BIN="/usr/bin/su"

if [ -f "$SU_BIN" ]; then
    # 그룹 확인 (wheel)
    SU_GROUP=$(stat -c "%G" "$SU_BIN")
    # 권한 확인 (4750 이하인지)
    SU_PERM=$(stat -c "%a" "$SU_BIN")

    # Ubuntu에서는 wheel 그룹 대신 sudo 그룹을 쓸 수도 있으나, 
    # 가이드 및 Ansible 코드(wheel) 기준에 맞춰 wheel로 점검
    if [ "$SU_GROUP" != "wheel" ] || [ "$SU_PERM" -gt 4750 ]; then
        FLAG_U_06_1=1
    else
        FLAG_U_06_1=0
    fi
else
    # 파일이 없으면 비정상 -> 취약
    FLAG_U_06_1=1
fi

# -------------------------
# 2) [U_06_2] PAM 설정 점검
# - 대상: /etc/pam.d/su
# - 기준: auth required pam_wheel.so ... 설정 존재 여부
# -------------------------
PAM_SU="/etc/pam.d/su"

if [ -f "$PAM_SU" ]; then
    # 주석 제외하고 pam_wheel.so 모듈 활성화 여부 확인
    if grep -v "^#" "$PAM_SU" | grep -q "pam_wheel.so"; then
        FLAG_U_06_2=0
    else
        FLAG_U_06_2=1
    fi
else
    # PAM 파일 없으면 취약
    FLAG_U_06_2=1
fi

# -------------------------
# 3) VULN_STATUS
# -------------------------
IS_VUL=0
if [ "$FLAG_U_06_1" -eq 1 ] || [ "$FLAG_U_06_2" -eq 1 ]; then
    IS_VUL=1
fi

# -------------------------
# 4) Output (JSON)
# -------------------------
cat <<EOF
{
  "meta": {
    "hostname": "$HOST",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "$FLAG_ID",
    "is_vul": $IS_VUL,
    "is_auto": $IS_AUTO,
    "category": "$CATEGORY",
    "flag": {
      "U_06_1": $FLAG_U_06_1,
      "U_06_2": $FLAG_U_06_2
    },
    "timestamp": "$DATE"
  }
}
EOF