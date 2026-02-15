#!/bin/bash

# [U-50] DNS Zone Transfer 설정
# 대상 운영체제 : Rocky Linux 9
# 가이드라인 출처 : KISA 주요정보통신기반시설 가이드 p.121-122
# 자동 조치 가능 유무 : 수동 조치 (named.conf 수정)
# 플래그 설명:
#   U_50_1 : [DNS] Zone Transfer 설정 미흡 (any 허용 또는 설정 누락)

# --- 점검 로직 시작 ---

# 초기화
U_50_1=0
IS_VUL=0

# 1. DNS 서비스 활성화 여부 확인
# 서비스가 활성화되어 있지 않으면(파일이 없거나 꺼져있으면) 양호로 간주
if systemctl is-active named >/dev/null 2>&1; then
    
    # 설정 파일 경로 설정 (Rocky Linux 9 기준)
    NAMED_BOOT="/etc/named.boot"
    NAMED_CONF="/etc/named.conf"
    
    # [Step 1] named.boot (구형) 점검 - 참고 코드 반영
    if [[ -f "$NAMED_BOOT" ]]; then
        if grep -i "xfrnets" "$NAMED_BOOT" >/dev/null 2>&1; then
            # xfrnets 설정이 있으면 일단 확인 필요(여기서는 로직상 넘어가고 named.conf를 주력으로 봄)
            :
        fi
    fi

    # [Step 2] named.conf (신형) 점검
    if [[ -f "$NAMED_CONF" ]]; then
        # 주석(#, //) 제거 후 allow-transfer 설정 추출
        # grep -r은 디렉토리가 아닐 경우 파일에서 검색
        # allow-transfer 구문이 있는지 확인
        ALLOW_TRANSFER=$(grep -vE "^#|^\/\/" "$NAMED_CONF" 2>/dev/null | grep "allow-transfer")
        
        if [[ -n "$ALLOW_TRANSFER" ]]; then
            # 설정이 존재하는 경우: 'any' 포함 여부 확인
            if echo "$ALLOW_TRANSFER" | grep -q "any"; then
                U_50_1=1 # 취약: 전체 허용
            fi
        else
            # 설정이 누락된 경우: 기본적으로 취약(전송 제한 없음)으로 간주 (참고 코드 기준)
            U_50_1=1 
        fi
    else
        # 서비스는 켜져있는데 설정 파일이 없는 경우 (특이 케이스)
        # 보안 설정 확인이 불가능하므로 취약으로 간주할 수 있으나, 
        # 일반적인 Rocky 환경을 고려하여 named.conf 부재 시 안전하게 처리하거나 에러 처리.
        # 여기서는 점검 불가로 1 처리
        U_50_1=1
    fi

fi

# 2. 전체 취약 여부 판단
IS_VUL=$U_50_1

# 3. JSON 출력
cat <<EOF
{
  "meta": {
    "hostname": "$(hostname)",
    "ip": "$(hostname -I | awk '{print $1}')",
    "user": "$(whoami)"
  },
  "result": {
    "flag_id": "U-50",
    "is_vul": $IS_VUL,
    "is_auto": 0,
    "category": "service",
    "flag": {
      "U_50_1": $U_50_1
    },
    "timestamp": "$(date "+%Y_%m_%d / %H:%M:%S")"
  }
}
EOF
