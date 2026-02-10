#!/usr/bin/bash 
##### [U-25] world writable 파일 점검
####### 점검내용: 불필요한 world writable 파일 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 :
####### [취약 조건] : world writable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_25_1=0


if [ `find / -type f -perm -2 2>/dev/null | wc -l` -gt 0 ]; then
		#echo "※ U-25 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " world writable 설정이 되어있는 파일이 있습니다." >> $resultfile 2>&1
		 U_25_1=1
else
		#echo "※ U-25 결과 : 양호(Good)" >> $resultfile 2>&1
		 U_25_1=0
fi
IS_VUL=$U_25_1
		 cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-25",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_25_1": $U_25_1,
    },
    "timestamp": "$DATE"
  }
}
EOF