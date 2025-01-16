-- cms_user 테이블 데이터
-- 사용자 1: 관리자
INSERT INTO cms_user (user_id, username, password, email, roles, active)
VALUES ('admin01', '관리자01', 'password1!', 'admin01@sample.com', 'ROLE_ADMIN', TRUE);

-- 사용자 2: 일반 사용자
INSERT INTO cms_user (user_id, username, password, email, roles, active)
VALUES ('user01', '사용자01', 'password1!', 'user01@sample.com', 'ROLE_USER', TRUE);
