#!/bin/bash

# [U-51] DNS 서비스의 취약한 동적 업데이트 설정 금지
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.122-123
# 자동 조치 가능 유무 : 불가능 (수동 설정 필요)
# 플래그 설명:
#   U_51_1 : [DNS] 동적 업데이트 전체 허용(any) 설정 발견

# --- 점검 로직 시작 ---

# 초기화
U_51_1=0
IS_VUL=0

# 1. DNS 서비스 활성화 여부 확인
# 서비스가 활성화되어 있지 않으면 양호
if systemctl is-active named >/dev/null 2>&1; then
    
    # 설정 파일 경로 설정 (Rocky Linux 9 기준)
    NAMED_CONF="/etc/named.conf"
    
    if [[ -f "$NAMED_CONF" ]]; then
        # 주석(#, //) 제거 후 allow-update 설정 추출
        ALLOW_UPDATE=$(grep -vE "^#|^\/\/" "$NAMED_CONF" 2>/dev/null | grep "allow-update")
        
        if [[ -n "$ALLOW_UPDATE" ]]; then
            # 설정이 존재하는 경우
            if echo "$ALLOW_UPDATE" | grep -q "any"; then
                # "any"가 포함되어 있으면 취약
                U_51_1=1
            else
                # "any"가 없으면 (none 또는 특정 IP) 양호
                U_51_1=0
            fi
        else
            # 설정이 없는 경우
            # 참고 코드 기준: "allow-update 설정이 명시되어 있지 않습니다." (Info) -> 취약 아님 (기본값 Deny)
            U_51_1=0
        fi
    else
        # 서비스는 켜져있으나 설정 파일이 없는 경우 (점검 불가)
        # 통상적으로 설정 파일 없이 데몬이 돌 수 없으므로 예외적 상황이나, 로직상 0(양호/판단불가) 처리
        U_51_1=0
    fi
fi

# 2. 전체 취약 여부 판단
IS_VUL=$U_51_1

# 3. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-51",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flags": {
      "U_51_1": $U_51_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
