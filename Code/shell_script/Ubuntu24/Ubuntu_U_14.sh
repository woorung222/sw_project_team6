#!/usr/bin/env bash
set -u

# =========================================================
# U_14 (상) root 홈, 패스 디렉터리 권한 및 패스 설정 | Ubuntu 24.04
# - 진단 기준: PATH 환경변수의 맨 앞이나 중간에 "." 또는 "::" 포함 여부 점검
# - DB 정합성: IS_AUTO=0 (환경변수 파손 위험으로 수동 조치 권장)
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_14"
CATEGORY="file"
IS_AUTO=0

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_14_1=0

# -------------------------
# 1) 현재 세션 PATH 점검 (가장 정확한 실시간 상태)
# -------------------------
if echo "$PATH" | grep -qE "^\.:|^::|:.:|::$"; then
    FLAG_U_14_1=1
fi

# -------------------------
# 2) 주요 환경 설정 파일 점검 (보조 확인)
# -------------------------
if [ "$FLAG_U_14_1" -eq 0 ]; then
    CHECK_FILES="/etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile"
    for file in $CHECK_FILES; do
        if [ -f "$file" ]; then
            # 주석 제외, PATH 설정 라인에서 취약 패턴 확인
            if grep -v "^#" "$file" | grep "PATH=" | grep -qE "\.:|::"; then
                FLAG_U_14_1=1
                break
            fi
        fi
    done
fi

# -------------------------
# 3) Output (JSON)
# -------------------------
IS_VUL=$FLAG_U_14_1

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
      "U_14_1": $FLAG_U_14_1
    },
    "timestamp": "$DATE"
  }
}
EOF