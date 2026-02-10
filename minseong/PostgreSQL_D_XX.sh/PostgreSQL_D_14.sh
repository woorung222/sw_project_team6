#!/usr/bin/bash 
##### [D-14] 데이터베이스의 주요 설정 파일, 비밀번호 파일 등과 같은 주요 파일들의 접근 권한이 적절하게 설정
####### 내용:데이터베이스의 주요 파일들에 대해 관리자를 제외한 일반 사용자의 파일 수정 권한을 제거하였는지 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: PostgreSQL 16
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 

[취약 조건]
주요 설정 파일 및 디렉터리의 권한 설정 시 일반 사용자의 수정 권한을 제거하지 않은 경우

---
[Unix OS] 

Step 1) 주요 설정 파일 위치 확인 postgresql.conf 파일 위치: [$datadir] DB 접속 통제 설정 파일 위치: /postgres/data/pg_hba.conf, /postgres/data/pg_ident.conf log_directory : /log_directory/pg_log

Step 2) 주요 설정 파일의 권한 설정 환경설정 파일(postgresql.conf)의 권한을 640 이하로 설정
chmod 640 [$datadir]/postgresql.conf DB접속 통제 설정 파일(pg_hba.conf, pg_ident.conf)의 권한을 640 이하로 설정 
chmod 640 ./pg_hba.conf 
chmod 640 ./pg_ident.conf 히스토리 파일 (.psql_history)의 권한을 600 이하로 설정 
$chmod 600 .psql_history Log 파일(pg_log)의 권한을 640 이하로 설정 
chmod 640 [Log 파일]

[Window OS]
다루지 않음