#!/usr/bin/bash 
##### [U-32]홈 디렉토리로 지정한 디렉토리의 존재 관리
####### 점검내용: 사용자 계정과 홈 디렉토리의 일치 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu 24.04
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 홈 디렉토리가 존재하지 않는 계정이 발견된 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_32_1=0

homedirectory_null_count=`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6==null' /etc/passwd | wc -l`
	if [ $homedirectory_null_count -gt 0 ]; then
		#echo "※ U-32 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
		#echo " 홈 디렉터리가 존재하지 않는 계정이 있습니다." >> $resultfile 2>&1
		 U_32_1=1
	else
		homedirectory_slash_count=`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $1!="root" && $6=="/"' /etc/passwd | wc -l`
		if [ $homedirectory_slash_count -gt 0 ]; then
			#echo "※ U-32 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
			#echo " 관리자 계정(root)이 아닌데 홈 디렉터리가 '/'로 설정된 계정이 있습니다." >> $resultfile 2>&1
			 U_32_1=1
		else
			#echo "※ U-32 결과 : 양호(Good)" >> $resultfile 2>&1
			 U_32_1=0
		fi
	fi
	IS_VUL=$U_32_1
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-32",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_32_1": $U_32_1,
    },
    "timestamp": "$DATE"
  }
}
EOF	 