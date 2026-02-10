#!/usr/bin/bash 
##### [D-11] DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근할 수 없도록 설정
####### 내용:시스템 테이블에 일반 사용자 계정이 접근할 수 없도록 설정되어 있는지 점검
####### 기준: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)
####### 대상: PostgreSQL 16
####### 자동 조치 가능 유무 : 
####### 자동 조치 불가능 사유 : 
####### [취약 조건] : 시스템 테이블에 DBA 외 일반 사용자 계정이 접근 가능하도록 설정되어 있는 경우

---

Step 1) 사용자 및 역할 권한 정보 조회
SELECT * FROM information_schema.role_table_grants; 

Step 2) 스키마명에 해당되는 Table에 대한 접근 권한을 일반 사용자로부터 제거
REVOKE [all,select,insert,update...] ON all tables IN schema '스키마명' FROM '계정명';
