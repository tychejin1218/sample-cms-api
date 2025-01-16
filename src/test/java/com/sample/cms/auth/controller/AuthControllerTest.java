package com.sample.cms.auth.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.common.type.ApiStatus;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@AutoConfigureMockMvc
@SpringBootTest
@ActiveProfiles("local")
class AuthControllerTest {

  @Autowired
  MockMvc mockMvc;

  @Autowired
  ObjectMapper objectMapper;

  @Transactional(readOnly = true)
  @DisplayName("Login 성공 - Status:200, statusCode:200")
  @Test
  void testAuthLoginSuccess() throws Exception {

    // Given
    String url = "/auth/login";

    String userId = "admin01";
    String password = "password1!";
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(userId, password);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(url)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(loginRequest))
    );

    // Then
    resultActions
        .andExpect(status().isOk())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("statusCode").value(ApiStatus.OK.getCode()))
        .andExpect(jsonPath("message").value(ApiStatus.OK.getMessage()))
        .andExpect(jsonPath("data.token").isNotEmpty())
        .andDo(print());
  }

  @Transactional(readOnly = true)
  @DisplayName("Login 실패 - 존재하지 않는 사용자 ID - Status:400, statusCode:805")
  @Test
  void testAuthLoginFailureNonExistentUserId() throws Exception {

    // Given
    String url = "/auth/login";

    String nonExistentUserId = "empty00";
    String password = "password1!";
    AuthDto.LoginRequest loginRequest = AuthDto.LoginRequest.of(nonExistentUserId, password);

    // When
    ResultActions resultActions = mockMvc.perform(
        post(url)
            .contentType(MediaType.APPLICATION_JSON)
            .content(objectMapper.writeValueAsString(loginRequest))
    );

    // Then
    resultActions
        .andExpect(status().isBadRequest())
        .andExpect(content().contentType(MediaType.APPLICATION_JSON))
        .andExpect(jsonPath("statusCode").value(ApiStatus.INVALID_CREDENTIALS.getCode()))
        .andExpect(jsonPath("message").value(ApiStatus.INVALID_CREDENTIALS.getMessage()))
        .andExpect(jsonPath("message").isNotEmpty())
        .andExpect(jsonPath("method").value(HttpMethod.POST.toString()))
        .andExpect(jsonPath("timestamp").isNotEmpty())
        .andDo(print());
  }
}
