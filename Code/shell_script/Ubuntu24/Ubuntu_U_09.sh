#!/usr/bin/env bash
set -u

# =========================================================
# U_09 (상) 계정이 존재하지 않는 GID 금지 점검 | Ubuntu 24.04
# - 진단 기준: GID 1000 이상의 그룹 중, 구성원이 없는 빈 그룹이 존재하면 취약
# - Rocky 논리 반영: /etc/group과 /etc/passwd 교차 검증
# =========================================================

HOST="$(hostname)"
IP="$(hostname -I | awk '{print $1}')"
USER="$(whoami)"
DATE="$(date "+%Y_%m_%d / %H:%M:%S")"

FLAG_ID="U_09"
CATEGORY="account"
IS_AUTO=0  # 그룹 삭제는 사이드 이펙트 우려로 수동 조치(0)

# -------------------------
# Flag (0: 양호, 1: 취약)
# -------------------------
FLAG_U_09_1=0

# -------------------------
# 1) [U_09_1] 빈 그룹 점검
# -------------------------
# /etc/passwd에서 현재 사용 중인 Primary GID 목록 추출
PRIMARY_GIDS=$(cut -d: -f4 /etc/passwd | sort -u)

if [ -f "/etc/group" ]; then
    while IFS=: read -r G_NAME G_PASS G_GID G_MEMBERS; do
        # GID가 숫자가 아니거나 비어있으면 건너뜀
        if ! [[ "$G_GID" =~ ^[0-9]+$ ]]; then continue; fi

        # Ubuntu/Rocky 기준 일반 그룹 시작 GID는 1000
        if [ "$G_GID" -ge 1000 ]; then
            # 1) 보조 그룹원(G_MEMBERS)이 비어있는지 확인 (4번째 필드)
            if [ -z "$G_MEMBERS" ]; then
                # 2) Primary GID로 사용되고 있는지 확인 (/etc/passwd)
                # grep -w로 정확한 매칭 확인
                if ! echo "$PRIMARY_GIDS" | grep -q -w "$G_GID"; then
                    # 구성원도 없고, 누구의 Primary GID도 아닌 경우 -> 취약
                    FLAG_U_09_1=1
                    # 하나라도 발견되면 루프 종료 (빠른 판단)
                    break
                fi
            fi
        fi
    done < /etc/group
fi

# -------------------------
# 2) VULN_STATUS
# -------------------------
IS_VUL=$FLAG_U_09_1

# -------------------------
# 3) Output (JSON)
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
      "U_09_1": $FLAG_U_09_1
    },
    "timestamp": "$DATE"
  }
}
EOF