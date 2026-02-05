#!/bin/bash

# [Master Scanner] Rocky_9 취약점 점검 통합 실행 스크립트
# 위치: /home/audit/scanner.sh

BASE_DIR="/home/audit/sw_project_team6/Choung/Rocky9_sh"
RESULT_DIR="$BASE_DIR/test"
TEMP_LOG="$RESULT_DIR/temp_scan.log"

# 1. 결과 저장 디렉토리 생성
mkdir -p "$RESULT_DIR"

echo "------------------------------------------------"
echo "  Rocky Linux 9 통합 보안 점검을 시작합니다."
echo "------------------------------------------------"

# 2. 실행할 스크립트 목록 확보 (Rocky_U_NN.sh 형태)
# 파일명에서 숫자(NN)만 추출하여 가장 큰 값을 찾기 위함
SCRIPTS=$(ls $BASE_DIR/Rocky_U_*.sh 2>/dev/null | sort -V)

if [ -z "$SCRIPTS" ]; then
    echo "실행할 점검 스크립트(.sh)가 존재하지 않습니다."
    exit 1
fi

# 3. 가장 큰 NN 번호 추출 (파일명에서 U_ 뒤의 숫자 추출)
MAX_NN=$(ls $BASE_DIR/Rocky_U_*.sh 2>/dev/null | grep -o 'U_[0-9]\+' | cut -d'_' -f2 | sort -rn | head -n 1)

# 최종 로그 파일 경로 설정
FINAL_LOG="$RESULT_DIR/debug_test_rocky9_${MAX_NN}.txt"

# 기존 임시 로그 초기화 및 시작 정보 기록
echo "점검 시작 시간: $(date)" > "$TEMP_LOG"
echo "대상 스크립트 개수: $(echo "$SCRIPTS" | wc -l)" >> "$TEMP_LOG"
echo "------------------------------------------------" >> "$TEMP_LOG"

# 4. 루프를 돌며 개별 스크립트 실행
for script in $SCRIPTS; do
    script_name=$(basename "$script")
    echo "[$script_name] 실행 중..."
    
    # 각 스크립트 실행 및 결과를 임시 로그에 추가
    # sudo 권한이 필요한 경우를 대비하여 세션 유지 필요할 수 있음
    bash "$script" >> "$TEMP_LOG" 2>&1
    
    echo "------------------------------------------------" >> "$TEMP_LOG"
done

# 5. 임시 로그를 최종 로그 명칭으로 변경
mv "$TEMP_LOG" "$FINAL_LOG"

echo "------------------------------------------------"
echo "  모든 점검이 완료되었습니다."
echo "  결과 파일: $FINAL_LOG"
echo "------------------------------------------------"
