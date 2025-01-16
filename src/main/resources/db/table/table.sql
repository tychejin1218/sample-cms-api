-- cms_user 테이블 존재하면 삭제
DROP TABLE IF EXISTS cms_user;

-- cms_user 테이블 생성
CREATE TABLE cms_user (
    id BIGINT AUTO_INCREMENT PRIMARY KEY COMMENT '기본 키',
    user_id VARCHAR(50) NOT NULL UNIQUE COMMENT '사용자 ID (로그인 ID)',
    user_name VARCHAR(100) NOT NULL COMMENT '사용자명',
    password VARCHAR(255) NOT NULL COMMENT '암호화된 비밀번호',
    email VARCHAR(255) NOT NULL UNIQUE COMMENT '이메일 주소',
    roles VARCHAR(255) COMMENT '사용자 역할 (예: ROLE_USER, ROLE_ADMIN)',
    active BOOLEAN DEFAULT TRUE COMMENT '계정 활성 여부'
) COMMENT='사용자 테이블' CHARSET=utf8mb4;

-- cms_user 테이블 인덱스 생성
CREATE INDEX idx_users_username ON cms_user(user_name);
CREATE INDEX idx_users_email ON cms_user(email);
