package com.sample.cms.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.hibernate.annotations.Comment;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
@Entity
@Table(name = "cms_user")
public class CmsUser {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  @Comment("기본 키") // 주석 추가
  private Long id;

  @Column(name = "user_id", nullable = false, unique = true, length = 50)
  @Comment("사용자 ID (로그인 ID)")
  private String userId;

  @Column(nullable = false, length = 100)
  @Comment("사용자명")
  private String username;

  @Column(nullable = false, length = 255)
  @Comment("암호화된 비밀번호")
  private String password;

  @Column(nullable = false, unique = true, length = 255)
  @Comment("이메일 주소")
  private String email;

  @Column(length = 255)
  @Comment("사용자 역할 (예: ROLE_USER, ROLE_ADMIN)")
  private String roles;

  @Column(nullable = false)
  @Comment("계정 활성 여부")
  private Boolean active;
}
