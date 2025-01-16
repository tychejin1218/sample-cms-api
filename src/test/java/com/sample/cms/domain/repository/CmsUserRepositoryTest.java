package com.sample.cms.domain.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.sample.cms.domain.entity.CmsUser;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest
@ActiveProfiles("local")
class CmsUserRepositoryTest {

  @Autowired
  private CmsUserRepository cmsUserRepository;

  private String userId;
  private String userName;
  private String nonExistentUserId;
  private String password;
  private String wrongPassword;

  @BeforeEach
  void init() {

    userId = "admin01";
    userName = "관리자01";
    nonExistentUserId = "empty00";
    password = "password1!";
    wrongPassword = "password00";
  }


  @Order(1)
  @Transactional
  @DisplayName("사용자 ID로 조회 성공")
  @Test
  void testFindByUserIdSuccess() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserId(userId);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isPresent(),
        () -> assertThat(optCmsUser.get().getUserId()).isEqualTo(userId),
        () -> assertThat(optCmsUser.get().getUsername()).isEqualTo(userName)
    );
  }

  @Order(2)
  @Transactional
  @DisplayName("존재하지 않는 사용자 ID 조회 실패")
  @Test
  void testFindByUserIdFailure() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserId(nonExistentUserId);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isNotPresent()
    );
  }

  @Order(3)
  @Transactional
  @DisplayName("사용자 ID와 비밀번호로 조회 성공")
  @Test
  void testFindByUserIdAndPasswordSuccess() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserIdAndPassword(userId, password);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isPresent(),
        () -> assertThat(optCmsUser.get().getUserId()).isEqualTo(userId),
        () -> assertThat(optCmsUser.get().getPassword()).isEqualTo(password) // 비밀번호도 확인
    );
  }

  @Order(4)
  @Transactional
  @Test
  @DisplayName("사용자 ID와 비밀번호로 조회 실패 - 비밀번호 불일치")
  void testFindByUserIdAndPasswordFailureWrongPassword() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserIdAndPassword(userId, wrongPassword);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isNotPresent()
    );
  }

  @Order(5)
  @Transactional
  @Test
  @DisplayName("사용자 ID와 비밀번호로 조회 실패 - 존재하지 않는 사용자 ID")
  void testFindByUserIdAndPasswordFailureNonExistentUserId() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserIdAndPassword(nonExistentUserId,
        password);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isNotPresent()
    );
  }
}
