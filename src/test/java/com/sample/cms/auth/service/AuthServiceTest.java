package com.sample.cms.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.auth.dto.AuthDto.LogoutRequest;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
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
  @DisplayName("로그인 성공 - 올바른 사용자 ID와 비밀번호를 입력하면 Access Token과 Refresh Token이 반환")
  @Test
  void testGetTokenByLoginSuccess() {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    // When
    AuthDto.LoginResponse loginResponse = authService.getTokenByLogin(loginRequest);
    log.debug("loginResponse: {}", loginResponse);

    // Then
    assertAll(
        () -> assertThat(loginResponse).isNotNull(),
        () -> assertThat(loginResponse.getAccessToken()).isNotNull(),
        () -> assertThat(loginResponse.getRefreshToken()).isNotNull()
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
  void testGetAccessTokenByRefreshTokenSuccess() throws InterruptedException {

    // Given
    AuthDto.LoginResponse loginResponse = getValidTokenByLogin();
    AuthDto.RefreshTokenRequest refreshTokenRequest =
        AuthDto.RefreshTokenRequest.of(loginResponse.getRefreshToken());

    TimeUnit.SECONDS.sleep(3);

    // When
    AuthDto.RefreshTokenResponse refreshTokenResponse =
        authService.getAccessTokenByRefreshToken(refreshTokenRequest);
    log.debug("refreshTokenResponse: {}", refreshTokenResponse);

    // Then
    assertAll(
        () -> assertThat(refreshTokenResponse).isNotNull(),
        () -> assertThat(refreshTokenResponse.getAccessToken()).isNotNull(),
        () -> assertThat(refreshTokenResponse.getAccessToken()).isNotEqualTo(
            loginResponse.getAccessToken())
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
        () -> assertThat(exception.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED),
        () -> assertThat(exception.getStatus()).isEqualTo(ApiStatus.INVALID_REFRESH_TOKEN)
    );
  }

  @Order(6)
  @Transactional
  @DisplayName("로그아웃 요청 성공: 효한 Access Token을 입력하면 로그아웃 처리와 사용자 ID 반환")
  @Test
  void testDeleteTokenByLogoutSuccess() {

    // Given
    AuthDto.LoginResponse loginResponse = getValidTokenByLogin();
    LogoutRequest logoutRequest = LogoutRequest.of(loginResponse.getAccessToken());

    // When
    AuthDto.LogoutResponse logoutResponse = authService.deleteTokenByLogout(logoutRequest);
    log.debug("logoutResponse: {}", logoutResponse);

    // Then
    assertAll(
        () -> assertThat(logoutResponse).isNotNull(),
        () -> assertThat(logoutResponse.getUserId()).isNotNull()
    );
  }

  /**
   * 로그인 요청을 처리하여 유효한 인증 정보를 반환
   *
   * @return 로그인 성공 시 발급된 액세스 및 리프레시 토큰 정보
   */
  private AuthDto.LoginResponse getValidTokenByLogin() {

    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    AuthDto.LoginResponse loginResponse = authService.getTokenByLogin(loginRequest);
    log.debug("getValidTokenByLogin loginResponse: {}", loginResponse);

    return loginResponse;
  }
}
