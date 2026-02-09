#!/bin/bash

# [U-09] 계정이 존재하지 않는 GID 금지 점검
# 대상 운영체제 : Rocky Linux 9
# 진단 기준 : GID 1000 이상의 그룹 중, 구성원(Primary/Secondary)이 없는 빈 그룹이 존재하면 취약

# 1. 메타 데이터 수집
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")

# 초기 상태 설정
U_09_1=0 
IS_VUL=0
VULN_GROUPS=""

# --- 점검 시작 ---

# 1. /etc/passwd에서 현재 사용 중인 Primary GID 목록 추출
# (임시 파일 생성 없이 변수에 저장)
PRIMARY_GIDS=$(cut -d: -f4 /etc/passwd | sort -u)

# 2. /etc/group 파일을 한 줄씩 읽으며 점검
# GID가 1000 이상인 그룹만 대상으로 함 (시스템 그룹 제외 목적)
while IFS=: read -r G_NAME G_PASS G_GID G_MEMBERS; do
    # GID가 숫자가 아닌 경우 건너뜀 (혹시 모를 오류 방지)
    if ! [[ "$G_GID" =~ ^[0-9]+$ ]]; then continue; fi

    # Rocky 9 기준 일반 그룹 시작 GID는 1000
    if [ "$G_GID" -ge 1000 ]; then
        # 1) 보조 그룹원(G_MEMBERS)이 비어있는지 확인
        if [ -z "$G_MEMBERS" ]; then
            # 2) Primary GID로 사용되고 있는지 확인
            # PRIMARY_GIDS 변수 안에 해당 GID가 존재하는지 grep으로 확인
            if ! echo "$PRIMARY_GIDS" | grep -q -w "$G_GID"; then
                # 아무도 사용하지 않는 1000번대 그룹 발견 -> 취약
                U_09_1=1
                VULN_GROUPS+="$G_NAME($G_GID) "
            fi
        fi
    fi
done < /etc/group

# --- 최종 결과 집계 ---
IS_VUL=$U_09_1

# --- JSON 출력 ---
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-09",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "account",
    "flag": {
      "U_09_1": $U_09_1
    },
    "timestamp": "$DATE"
  }
}
EOF