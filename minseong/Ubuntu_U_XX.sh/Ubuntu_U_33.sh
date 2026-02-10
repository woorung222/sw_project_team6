#!/usr/bin/bash 
##### [U-33]숨겨진 파일 및 디렉토리 검색 및 제거
####### 점검내용: 숨겨진 파일 및 디렉토리 내 의심스러운 파일 존재 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu 24.04
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 불필요하거나 의심스러운 숨겨진 파일 및 디렉토리를 제거하지 않은 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_33_1=0


if [ `find / -name '.*' -type f 2>/dev/null | wc -l` -gt 0 ]; then
		#echo "※ U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " 숨겨진 파일이 있습니다." >> $resultfile 2>&1
		 U_33_1=1
	elif [ `find / -name '.*' -type d 2>/dev/null | wc -l` -gt 0 ]; then
		#echo "※ U-33 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " 숨겨진 디렉터리가 있습니다." >> $resultfile 2>&1
		 U_33_1=1
	else
		#echo "※ U-33 결과 : 양호(Good)" >> $resultfile 2>&1$resultfile 2>&1
		 U_33_1=0
	fi
IS_VUL=$U_33_1
	cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-33",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_33_1": $U_33_1,
    },
    "timestamp": "$DATE"
  }
}
EOF	 