#!/usr/bin/bash 
##### [U-24] 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
####### 점검내용: 홈 디렉터리 내의 환경변수 파일에 대한 소유자 및 접근 권한이 관리자 또는 해당 계정으로 설정 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] :홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정으로 지정되지 않거나, 홈 디렉터리 환경변수 파일에 root 계정과 소유자 외에 쓰기 권한이 부여된 경우

#---
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_24_1=0


user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
	user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
	done
	user_homedirectory_owner_name=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $1}' /etc/passwd`) # /etc/passwd 파일에 설정된 사용자명 배열 생성
	user_homedirectory_owner_name2=() # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 저장할 빈 배열 생성
	for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
	do
		user_homedirectory_owner_name2[${#user_homedirectory_owner_name2[@]}]=`echo ${user_homedirectory_path2[$i]} | awk -F / '{print $3}'` # user_homedirectory_path2 배열에서 사용자명만 따로 출력하여 배열에 저장함
	done
	for ((i=0; i<${#user_homedirectory_owner_name2[@]}; i++))
	do
		user_homedirectory_owner_name[${#user_homedirectory_owner_name[@]}]=${user_homedirectory_owner_name2[$i]} # 두 개의 배열 합침
	done
	start_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
	for ((i=0; i<${#user_homedirectory_path[@]}; i++))
	do
		for ((j=0; j<${#start_files[@]}; j++))
		do
			if [ -f ${user_homedirectory_path[$i]}/${start_files[$j]} ]; then
				user_homedirectory_owner_name2=`ls -l ${user_homedirectory_path[$i]}/${start_files[$j]} | awk '{print $3}'`
				if [[ $user_homedirectory_owner_name2 =~ root ]] || [[ $user_homedirectory_owner_name2 =~ ${user_homedirectory_owner_name[$i]} ]]; then
					user_homedirectory_other_execute_permission=`ls -l ${user_homedirectory_path[$i]}/${start_files[$j]} | awk '{print substr($1,9,1)}'`
					if [[ $user_homedirectory_other_execute_permission =~ w ]]; then
						#echo "※ U-24 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
						#echo " ${user_homedirectory_path[$i]} 홈 디렉터리 내 ${start_files[$j]} 환경 변수 파일에 다른 사용자(other)의 쓰기(w) 권한이 부여 되어 있습니다." >> $resultfile 2>&1
						 U_24_1=1

					fi
				else
					#echo "※ U-24 결과 : 취약(Vulnerable)" >> $resultfile 2>&1
					#echo " ${user_homedirectory_path[$i]} 홈 디렉터리 내 ${start_files[$j]} 환경 변수 파일의 소유자(owner)가 root 또는 해당 계정이 아닙니다." >> $resultfile 2>&1
					 U_24_1=1

				fi
			fi
		done
	done
	#echo "※ U-24 결과 : 양호(Good)" >> $resultfile 2>&1
	IS_VUL=$U_24_1
	 cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-24",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_24_1": $U_24_1,
    },
    "timestamp": "$DATE"
  }
}
EOF