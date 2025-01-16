package com.sample.cms.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SpringBootTest
@ActiveProfiles("local")
class AuthServiceTest {

  @Autowired
  AuthService authService;

  @Order(1)
  @Transactional(readOnly = true)
  @DisplayName("로그인 성공 - 올바른 사용자 ID 및 비밀번호")
  @Test
  void testAuthLoginSuccess() {

    // Given
    String userId = "admin01";
    String password = "password1!";

    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    // When
    AuthDto.LoginResponse loginResponse = authService.authLogin(loginRequest);

    // Then
    assertAll(
        () -> assertThat(loginResponse).isNotNull(),
        () -> assertThat(loginResponse.getToken()).isNotNull()
    );
  }

  @Order(2)
  @Transactional
  @DisplayName("로그인 실패 - 비밀번호 불일치")
  @Test
  void testAuthLoginFailureWrongPassword() {

    // Given
    String userId = "admin01";
    String wrongPassword = "password00";

    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, wrongPassword);

    // When
    ApiException exception = assertThrows(ApiException.class,
        () -> authService.authLogin(loginRequest));

    // Then
    assertAll(
        () -> assertThat(exception.getStatus()).isEqualTo(ApiStatus.INVALID_REQUEST)
    );
  }

  @Order(2)
  @Transactional
  @DisplayName("로그인 실패 - 존재하지 않는 사용자 ID")
  @Test
  void testAuthLoginFailureNonExistentUserId() {

    // Given
    String nonExistentUserId = "empty00";
    String password = "password1!";

    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(nonExistentUserId, password);

    // When
    ApiException exception = assertThrows(ApiException.class,
        () -> authService.authLogin(loginRequest));

    // Then
    assertAll(
        () -> assertThat(exception.getStatus()).isEqualTo(ApiStatus.INVALID_REQUEST)
    );
  }
}
