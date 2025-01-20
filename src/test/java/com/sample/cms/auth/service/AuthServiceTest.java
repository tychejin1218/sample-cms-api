package com.sample.cms.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.auth.dto.AuthDto.LogoutRequest;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
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

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SpringBootTest
@ActiveProfiles("local")
class AuthServiceTest {

  @Autowired
  AuthService authService;

  private String userId;
  private String password;
  private String nonExistentUserId;
  private String wrongPassword;

  @BeforeEach
  void init() {
    userId = "admin01";
    password = "password1!";
    nonExistentUserId = "empty00";
    wrongPassword = "password0!";
  }

  @Order(1)
  @Transactional(readOnly = true)
  @DisplayName("로그인 성공 - 올바른 사용자 ID와 비밀번호를 입력하면 Access Token과 Refresh Token이 발급")
  @Test
  void testGetTokenByLoginSuccess() {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    // When
    AuthDto.TokenResponse tokenResponse = authService.getTokenByLogin(loginRequest);
    log.debug("tokenResponse: {}", tokenResponse);

    // Then
    assertAll(
        () -> assertThat(tokenResponse).isNotNull(),
        () -> assertThat(tokenResponse.getAccessToken()).isNotNull(),
        () -> assertThat(tokenResponse.getRefreshToken()).isNotNull()
    );
  }

  @Order(2)
  @Transactional
  @DisplayName("로그인 실패 - 존재하지 않는 사용자 ID를 입력하면 ApiException이 발생")
  @Test
  void testGetTokenByLoginFailureNonExistentUserId() {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(nonExistentUserId, password);

    // When
    ApiException exception = assertThrows(ApiException.class,
        () -> authService.getTokenByLogin(loginRequest));

    // Then
    assertAll(
        () -> assertThat(exception.getStatus()).isEqualTo(ApiStatus.INVALID_CREDENTIALS)
    );
  }

  @Order(3)
  @Transactional
  @DisplayName("로그인 실패 - 비밀번호가 일치하지 않으면 ApiException이 발생")
  @Test
  void testGetTokenByLoginFailureWrongPassword() {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, wrongPassword);

    // When
    ApiException exception = assertThrows(ApiException.class,
        () -> authService.getTokenByLogin(loginRequest));

    // Then
    assertAll(
        () -> assertThat(exception.getStatus()).isEqualTo(ApiStatus.INVALID_CREDENTIALS)
    );
  }

  @Order(4)
  @Transactional
  @DisplayName("Access Token 재발급 성공: 유효한 Refresh Token을 입력하면 새로운 Access Token이 발급")
  @Test
  void testGetAccessTokenByRefreshTokenSuccess() {

    // Given
    String validRefreshToken = getValidRefreshToken();
    AuthDto.RefreshTokenRequest refreshTokenRequest =
        AuthDto.RefreshTokenRequest.of(validRefreshToken);

    // When
    AuthDto.RefreshTokenResponse refreshTokenResponse =
        authService.getAccessTokenByRefreshToken(refreshTokenRequest);
    log.debug("refreshTokenResponse: {}", refreshTokenResponse);

    // Then
    assertAll(
        () -> assertThat(refreshTokenResponse).isNotNull(),
        () -> assertThat(refreshTokenResponse.getAccessToken()).isNotNull()
    );
  }

  @Order(5)
  @Transactional
  @DisplayName("Access Token 재발급 실패: 유효하지 않은 Refresh Token을 입력하면 ApiException이 발생")
  @Test
  void testGetAccessTokenByRefreshTokenFailureInvalidRefreshToken() {

    // Given
    String invalidRefreshToken = "invalid_refresh_token";
    AuthDto.RefreshTokenRequest refreshTokenRequest = AuthDto.RefreshTokenRequest.of(
        invalidRefreshToken);

    // When
    ApiException exception = assertThrows(ApiException.class,
        () -> authService.getAccessTokenByRefreshToken(refreshTokenRequest));

    // Then
    assertAll(
        () -> assertThat(exception.getStatus()).isEqualTo(ApiStatus.INVALID_REFRESH_TOKEN)
    );
  }

  @Order(6)
  @Transactional
  @DisplayName("")
  @Test
  void testLogout() {

    // Given
    String accessToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbjAxIiwicm9sZUxpc3QiOlsiUk9MRV9BRE1JTiJdLCJpYXQiOjE3MzczNjE1MTksImV4cCI6MTczNzM2ODcxOX0.PF9FnIBcgCRCFwVKXu702aDC8-QbnFqK1-lMuxi_pEY";
    LogoutRequest logoutRequest = LogoutRequest.of(accessToken);

    // When
    authService.logout(logoutRequest);

    // Then

  }

  /**
   * 로그인 요청을 통해 유효한 Refresh Token을 반환
   *
   * @return 로그인 성공으로 발급받은 Refresh Token
   */
  private String getValidRefreshToken() {

    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    AuthDto.TokenResponse tokenResponse = authService.getTokenByLogin(loginRequest);
    log.debug("getValidRefreshToken tokenResponse: {}", tokenResponse);

    return tokenResponse.getRefreshToken();
  }
}
