#!/usr/bin/bash 
##### [U-31]홈디렉토리 소유자 및 권한 설정
####### 점검내용: 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu 24.04
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 홈 디렉토리의 소유자 외 타 사용자가 해당 홈 디렉토리를 수정할 수 없도록 제한 설정 여부 점검

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_31_1=0

user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	user_homedirectory_owner_name=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $1}' /etc/passwd`) # /etc/passwd 파일에 설정된 사용자명 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]=`echo ${user_homedirectory_path2[$i]} | awk -F / '{print $3}'` # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장함
	done
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		if [ -d ${user_homedirectory_path[$i]} ]; then
			homedirectory_owner_name=`ls -ld ${user_homedirectory_path[$i]} | awk '{print $3}'`
			if [[ $homedirectory_owner_name =~ ${user_homedirectory_owner_name[$i]} ]]; then
				homedirectory_other_permission=`stat ${user_homedirectory_path[$i]} | grep -i 'Uid' | awk '{print $2}' | awk -F / '{print substr($1,5,1)}'`
				if [ $homedirectory_other_permission -eq 7 ] || [ $homedirectory_other_permission -eq 6 ] || [ $homedirectory_other_permission -eq 3 ] || [ $homedirectory_other_permission -eq 2 ]; then
					#echo "※ U-31 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " ${user_homedirectory_path[$i]} 홈 디렉터리에 다른 사용자(other)의 쓰기 권한이 부여되어 있습니다." >> $resultfile 2>&1
					 U_31_1=1

				fi
			else
				#echo "※ U-31 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
				#echo " ${user_homedirectory_path[$i]} 홈 디렉터리의 소유자가 ${user_homedirectory_owner_name[$i]}이(가) 아닙니다." >> $resultfile 2>&1
				 U_31_1=1
			fi
		fi
	done
	#echo "※ U-31 결과 : 양호(Good)" >> $resultfile 2>&1
	IS_VUL=$U_31_1
	 cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-31",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_31_1": $U_31_1,
    },
    "timestamp": "$DATE"
  }
}
EOF	 