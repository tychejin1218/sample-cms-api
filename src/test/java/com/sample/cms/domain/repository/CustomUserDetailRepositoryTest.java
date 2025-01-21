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
class CustomUserDetailRepositoryTest {

  @Autowired
  private CmsUserRepository cmsUserRepository;

  private String userId;
  private String nonExistentUserId;

  @BeforeEach
  void init() {
    userId = "admin01";
    nonExistentUserId = "empty00";
  }

  @Order(1)
  @Transactional
  @DisplayName("사용자 ID로 조회 시 존재하는 사용자 반환")
  @Test
  void testFindByUserIdSuccess() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserId(userId);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isPresent(),
        () -> assertThat(optCmsUser.get().getUserId()).isEqualTo(userId)
    );
  }

  @Order(2)
  @Transactional
  @DisplayName("존재하지 않는 사용자 ID로 조회 시 비어 있는 Optional 반환")
  @Test
  void testFindByUserIdFailure() {

    // Given & When
    Optional<CmsUser> optCmsUser = cmsUserRepository.findByUserId(nonExistentUserId);

    // Then
    assertAll(
        () -> assertThat(optCmsUser).isNotPresent()
    );
  }
}
