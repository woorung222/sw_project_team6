#!/usr/bin/env bash
set -u

# =========================================================
# U_11 (상) 사용자 Shell 점검 | Ubuntu 24.04
# - 진단 기준: 로그인이 필요 없는 계정(daemon, bin 등)에 
#             /bin/false 또는 /usr/sbin/nologin 쉘이 부여되었는지 점검
# - Rocky 논리 반영: 대상 계정 목록 일치화
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_11"
CATEGORY="account"
IS_AUTO=1  # 쉘 변경은 자동화 가능

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_11_1=0

# -------------------------
# 1) [U_11_1] 시스템 계정 쉘 점검
# -------------------------
# 점검 대상 계정 (Rocky와 동일하게 설정)
CHECK_LIST="daemon bin sys adm listen nobody nobody4 noaccess diag operator games gopher"
VULN_FOUND=0

for acc in $CHECK_LIST; do
    # /etc/passwd에 계정이 있는지 확인
    if grep -q "^$acc:" /etc/passwd; then
        # 쉘(7번째 필드) 추출
        SHELL=$(grep "^$acc:" /etc/passwd | awk -F: '{print $7}')
        
        # Ubuntu는 /usr/sbin/nologin 또는 /bin/false 사용
        # (혹시 모를 /sbin/nologin도 허용 목록에 포함)
        if [ "$SHELL" != "/bin/false" ] && \
           [ "$SHELL" != "/usr/sbin/nologin" ] && \
           [ "$SHELL" != "/sbin/nologin" ]; then
            VULN_FOUND=1
            # 하나라도 취약하면 루프 종료 가능 (또는 로그를 위해 계속 돌릴 수 있음)
            break
        fi
    fi
done

if [ "$VULN_FOUND" -eq 1 ]; then
    FLAG_U_11_1=1
else
    FLAG_U_11_1=0
fi

# -------------------------
# 2) Output (JSON)
# -------------------------
IS_VUL=$FLAG_U_11_1

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
      "U_11_1": $FLAG_U_11_1
    },
    "timestamp": "$DATE"
  }
}
EOF