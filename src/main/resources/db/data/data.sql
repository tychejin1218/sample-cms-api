-- cms_user 테이블 데이터
-- 사용자 1: 관리자
INSERT INTO cms_user (user_id, user_name, password, email, roles, active)
VALUES ('admin01', '관리자01', '$2a$10$OfaL4ewb8jPnF7qIScJBTOFvmxv1seF36h0pCk0RjosFBvaQWkZJa', 'admin01@sample.com', 'ROLE_ADMIN', TRUE);

-- 사용자 2: 일반 사용자
INSERT INTO cms_user (user_id, user_name, password, email, roles, active)
VALUES ('user01', '사용자01', '$2a$10$OfaL4ewb8jPnF7qIScJBTOFvmxv1seF36h0pCk0RjosFBvaQWkZJa', 'user01@sample.com', 'ROLE_USER', TRUE);
