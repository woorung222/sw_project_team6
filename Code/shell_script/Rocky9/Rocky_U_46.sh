#!/bin/bash

# [U-46] 일반 사용자의 메일 서비스 실행 방지
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.111-112
# 자동 조치 가능 유무 : 가능 (설정 변경 및 권한 수정)
# 플래그 설명:
#   U_46_1 : [Sendmail] restrictqrun 옵션 누락
#   U_46_2 : [Postfix] /usr/sbin/postsuper 일반 사용자 실행 권한(o+x) 존재
#   U_46_3 : [Exim] /usr/sbin/exiqgrep 일반 사용자 실행 권한(o+x) 존재

# --- 점검 로직 시작 ---

# 초기화
U_46_1=0
U_46_2=0
U_46_3=0

# 1. [Sendmail] 점검 (U_46_1)
if systemctl is-active sendmail >/dev/null 2>&1; then
    CF_FILE="/etc/mail/sendmail.cf"
    if [[ -f "$CF_FILE" ]]; then
        # PrivacyOptions 행에서 restrictqrun 옵션 확인 (주석 제외)
        if ! grep -v "^#" "$CF_FILE" 2>/dev/null | grep -i "PrivacyOptions" | grep -iq "restrictqrun"; then
            U_46_1=1
        fi
    else
        # 서비스는 활성 상태인데 설정 파일이 없으면 취약으로 간주
        U_46_1=1
    fi
fi

# 2. [Postfix] 점검 (U_46_2)
if systemctl is-active postfix >/dev/null 2>&1; then
    TARGET_BIN="/usr/sbin/postsuper"
    if [[ -f "$TARGET_BIN" ]]; then
        PERM=$(stat -c "%a" "$TARGET_BIN")
        OTHER_PERM=${PERM: -1} # 마지막 자리 (Other)
        
        # Other 권한이 홀수(1, 3, 5, 7)면 실행(x) 권한 있음 -> 취약
        if [[ $((OTHER_PERM % 2)) -eq 1 ]]; then
            U_46_2=1
        fi
    fi
fi

# 3. [Exim] 점검 (U_46_3)
if systemctl is-active exim >/dev/null 2>&1; then
    TARGET_BIN="/usr/sbin/exiqgrep"
    if [[ -f "$TARGET_BIN" ]]; then
        PERM=$(stat -c "%a" "$TARGET_BIN")
        OTHER_PERM=${PERM: -1}
        
        # Other 권한이 홀수면 실행 권한 있음 -> 취약
        if [[ $((OTHER_PERM % 2)) -eq 1 ]]; then
            U_46_3=1
        fi
    fi
fi

# 4. 전체 취약 여부 판단
IS_VUL=0
if [[ $U_46_1 -eq 1 ]] || [[ $U_46_2 -eq 1 ]] || [[ $U_46_3 -eq 1 ]]; then
    IS_VUL=1
fi

# 5. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-46",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "service",
    "flag": {
      "U_46_1": $U_46_1,
      "U_46_2": $U_46_2,
      "U_46_3": $U_46_3
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
