package com.sample.cms.auth.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.common.constants.Constants;
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
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@AutoConfigureMockMvc
@SpringBootTest
@ActiveProfiles("local")
class AuthControllerTest {

  @Autowired
  MockMvc mockMvc;

  @Autowired
  ObjectMapper objectMapper;

  private static final String LOGIN_URL = "/auth/login";
  private static final String REFRESH_TOKEN_URL = "/auth/refresh-token";

  private static final String JSON_PATH_STATUS_CODE = "statusCode";
  private static final String JSON_PATH_MESSAGE = "message";
  private static final String JSON_PATH_DATA = "data";
  private static final String JSON_PATH_METHOD = "method";
  private static final String JSON_PATH_TIMESTAMP = "timestamp";

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
  @DisplayName("로그인 성공 - 올바른 사용자 ID와 비밀번호를 입력하면 Access Token과 Refresh Token이 발급"
      + "_Status:200, statusCode:200")
  @Test
  void testAuthLoginSuccess() throws Exception {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(LOGIN_URL)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(loginRequest))
    );

    // Then
    resultActions
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.OK.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.OK.getMessage()))
        .andDo(print());
  }

  @Order(2)
  @Transactional(readOnly = true)
  @DisplayName("로그인 실패: 존재하지 않는 사용자 ID를 입력하면 ApiException이 발생"
      + "_Status:400, statusCode:805")
  @Test
  void testAuthLoginFailureNonExistentUserId() throws Exception {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(nonExistentUserId, password);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(LOGIN_URL)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(loginRequest))
    );

    // Then
    resultActions
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.INVALID_CREDENTIALS.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.INVALID_CREDENTIALS.getMessage()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).isNotEmpty())
        .andExpect(jsonPath(JSON_PATH_METHOD).value(HttpMethod.POST.toString()))
        .andExpect(jsonPath(JSON_PATH_TIMESTAMP).isNotEmpty())
        .andDo(print());
  }

  @Order(3)
  @Transactional(readOnly = true)
  @DisplayName("로그인 실패: 존재하지 않는 사용자 ID를 입력하면 ApiException이 발생"
      + "_Status:400, statusCode:805")
  @Test
  void testAuthLoginFailureWrongPassword() throws Exception {

    // Given
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, wrongPassword);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(LOGIN_URL)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(loginRequest))
    );

    // Then
    resultActions
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.INVALID_CREDENTIALS.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.INVALID_CREDENTIALS.getMessage()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).isNotEmpty())
        .andExpect(jsonPath(JSON_PATH_METHOD).value(HttpMethod.POST.toString()))
        .andExpect(jsonPath(JSON_PATH_TIMESTAMP).isNotEmpty())
        .andDo(print());
  }

  @Order(4)
  @Transactional
  @DisplayName("Access Token 재발급 성공: 유효한 Refresh Token을 입력하면 새로운 Access Token이 발급"
      + "_Status:200, statusCode:200")
  @Test
  void testAuthRefreshTokenSuccess() throws Exception {

    // Given
    AuthDto.LoginResponse loginResponse = getValidTokenByLogin();
    AuthDto.RefreshTokenRequest refreshTokenRequest = AuthDto.RefreshTokenRequest.of(
        loginResponse.getRefreshToken());

    TimeUnit.SECONDS.sleep(3);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(REFRESH_TOKEN_URL)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(refreshTokenRequest))
    );

    // Then
    resultActions
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.OK.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.OK.getMessage()))
        .andExpect(jsonPath(JSON_PATH_DATA + ".accessToken").isNotEmpty())
        .andDo(print());
  }

  @Order(5)
  @Transactional
  @DisplayName("Access Token 재발급 실패: 유효하지 않은 Refresh Token을 입력하면 ApiException이 발생"
      + "_Status:401, statusCode:810")
  @Test
  void testAuthRefreshTokenFailureInvalidToken() throws Exception {

    // Given
    String invalidRefreshToken = "invalid_refresh_token";
    AuthDto.RefreshTokenRequest refreshTokenRequest = AuthDto.RefreshTokenRequest.of(
        invalidRefreshToken);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(REFRESH_TOKEN_URL)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(refreshTokenRequest))
    );

    // Then
    resultActions
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.INVALID_REFRESH_TOKEN.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.INVALID_REFRESH_TOKEN.getMessage()))
        .andExpect(jsonPath(JSON_PATH_DATA).doesNotExist())
        .andDo(print());
  }

  @Order(6)
  @Transactional
  @DisplayName("로그아웃 성공: Refresh Token 삭제 및 Access Token 블랙리스트 처리 성공"
      + "_Status:200, statusCode:200")
  @Test
  void testAuthLogoutSuccess() throws Exception {

    // Given
    AuthDto.LoginResponse loginResponse = getValidTokenByLogin();
    AuthDto.LogoutRequest logoutRequest = AuthDto.LogoutRequest.of(loginResponse.getAccessToken());

    // When
    ResultActions resultActions = mockMvc.perform(
        post("/auth/logout")
            .header(Constants.AUTHORIZATION,
                Constants.BEARER + " " + loginResponse.getAccessToken())
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(logoutRequest))
    );

    // Then
    resultActions
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.OK.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.OK.getMessage()))
        .andExpect(jsonPath("data.userId").isNotEmpty())
        .andDo(print());
  }

  @Order(7)
  @Transactional
  @DisplayName("로그아웃 실패: 유효하지 않은  Access Token이 주어졌을 때 ApiException 발생"
      + "_Status:401, statusCode:810")
  @Test
  void testAuthLogoutFailureInvalidToken() throws Exception {

    // Given
    AuthDto.LoginResponse loginResponse = getValidTokenByLogin();
    String invalidRefreshToken = "invalid_refresh_token";
    AuthDto.LogoutRequest logoutRequest = AuthDto.LogoutRequest.of(invalidRefreshToken);

    // When
    ResultActions resultActions = mockMvc.perform(
        post("/auth/logout")
            .header(Constants.AUTHORIZATION,
                Constants.BEARER + " " + loginResponse.getAccessToken())
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(logoutRequest))
    );

    // Then
    resultActions
        .andExpect(status().isUnauthorized())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath(JSON_PATH_STATUS_CODE).value(ApiStatus.INVALID_REFRESH_TOKEN.getCode()))
        .andExpect(jsonPath(JSON_PATH_MESSAGE).value(ApiStatus.INVALID_REFRESH_TOKEN.getMessage()))
        .andExpect(jsonPath(JSON_PATH_DATA).doesNotExist())
        .andDo(print());
  }

  /**
   * 로그인 요청을 처리하여 유효한 인증 정보를 반환
   *
   * @return 로그인 성공 시 발급된 액세스 및 리프레시 토큰 정보
   */
  private AuthDto.LoginResponse getValidTokenByLogin() throws Exception {

    String loginUrl = "/auth/login";
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    ResultActions resultActions = mockMvc.perform(
        post(loginUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(loginRequest))
    );

    String content = resultActions.andReturn().getResponse().getContentAsString();
    String accessToken = objectMapper.readTree(content).get("data").get("accessToken").asText();
    String refreshToken = objectMapper.readTree(content).get("data").get("refreshToken").asText();

    return AuthDto.LoginResponse.of(accessToken, refreshToken);
  }
}
