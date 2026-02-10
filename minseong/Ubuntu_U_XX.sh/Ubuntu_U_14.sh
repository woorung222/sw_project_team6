#!/usr/bin/bash 
##### [U-14]root 홈, 패스 디렉터리 권한 및 패스 설정
####### 점검내용: root 계정의 PATH 환경변수에 “.”(마침표)이 포함 여부 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: Ubuntu
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함된 경우
HOSTNAME=$(hostname)
IP=$(hostname -I | awk '{print $1}')
CURRENT_USER=$(whoami)
DATE=$(date "+%Y_%m_%d / %H:%M:%S")
resultfile="Results_$(date '+%F').txt"
IS_VUL=0
U_14_1=0

#echo ""   > $resultfile 2>&1
	#echo "▶ U-14(상) | 2. 파일 및 디렉토리 관리 > 2.1 root홈, 패스 디렉터리 권한 및 패스 설정 ◀"   > $resultfile 2>&1
	#echo " 양호 판단 기준 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우"   > $resultfile 2>&1
	if [ `echo $PATH | grep -E '\.:|::' | wc -l` -gt 0 ]; then
		#echo "※ U-14 결과 : 취약(Vulnerable)"  > $resultfile 2>&1
		#echo " PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다."  > $resultfile 2>&1
		U_14_1=1
	else
		# /etc 디렉터리 내 설정 파일의 PATH 변수 중 누락이 있을 가능성을 생각하여 추가 확인함
		path_settings_files=("/etc/profile" "/etc/.login" "/etc/csh.cshrc" "/etc/csh.login" "/etc/environment")
		for ((i=0; i<${#path_settings_files[@]}; i++))
		do
			if [ -f ${path_settings_files[$i]} ]; then
				path_settings_file_path_variable_exists_count=`grep -vE '^#|^\s#' ${path_settings_files[$i]} | grep 'PATH=' | wc -l`
				if [ $path_settings_file_path_variable_exists_count -gt 0 ]; then
					path_settings_file_path_variable_value_count=`grep -vE '^#|^\s#' ${path_settings_files[$i]} | grep 'PATH=' | grep -E '\.:|::' | wc -l`
					if [ $path_settings_file_path_variable_value_count -gt 0 ]; then
						#echo "※ U-14 결과 : 취약(Vulnerable)"  > $resultfile 2>&1
						#echo " /etc 디렉터리 내 Start Profile에 설정된 PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다."  > $resultfile 2>&1
						U_14_1=1
					fi
				fi
			fi
		done
		# 사용자 홈 디렉터리 내 설정 파일의 PATH 변수 중 누락이 있을 가능성을 생각하여 추가 확인함
		path_settings_files=(".profile" ".cshrc" ".login" ".kshrc" ".bash_profile" ".bashrc" ".bash_login")
		user_homedirectory_path=(`awk -F : '$7!="/bin/false" && $7!="/sbin/nologin" && $6!=null {print $6}' /etc/passwd | uniq`) # /etc/passwd 파일에 설정된 홈 디렉터리 배열 생성
		user_homedirectory_path2=(/home/*) # /home 디렉터래 내 위치한 홈 디렉터리 배열 생성
		for ((i=0; i<${#user_homedirectory_path2[@]}; i++))
		do
			user_homedirectory_path[${#user_homedirectory_path[@]}]=${user_homedirectory_path2[$i]} # 두 개의 배열 합침
		done
		user_homedirectory_path[${#user_homedirectory_path[@]}]=/root
		for ((i=0; i<${#user_homedirectory_path[@]}; i++))
		do
			for ((j=0; j<${#path_settings_files[@]}; j++))
			do
				if [ -f ${user_homedirectory_path[$i]}/${path_settings_files[$j]} ]; then
					path_settings_file_path_variable_exists_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${path_settings_files[$j]} | grep 'PATH=' | wc -l`
					if [ $path_settings_file_path_variable_exists_count -gt 0 ]; then
						path_settings_file_path_variable_value_count=`grep -vE '^#|^\s#' ${user_homedirectory_path[$i]}/${path_settings_files[$j]} | grep 'PATH=' | grep -E '\.:|::' | wc -l`
						if [ $path_settings_file_path_variable_value_count -gt 0 ]; then
							#echo "※ U-14 결과 : 취약(Vulnerable)"  > $resultfile 2>&1
							#echo " ${user_homedirectory_path[$i]} 디렉터리 내 ${path_settings_files[$j]} 파일에 설정된 PATH 환경 변수 내에 "." 또는 "::"이 포함되어 있습니다."  > $resultfile 2>&1
							U_14_1=1

						fi
					fi
				fi
			done
		done
	fi
	#echo "※ U-14 결과 : 양호(Good)"  > $resultfile 2>&1

	IS_VUL=$U_14_1
cat <<EOF
{
  "meta": {
    "hostname": "$HOSTNAME",
    "ip": "$IP",
    "user": "$USER"
  },
  "result": {
    "flag_id": "U-14",
    "is_vul": $IS_VUL,
    "is_auto": 1,
    "category": "file",
    "flag": {
      "U_14_1": $U_14_1,
    },
    "timestamp": "$DATE"
  }
}
EOF