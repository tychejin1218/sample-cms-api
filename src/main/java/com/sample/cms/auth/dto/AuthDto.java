package com.sample.cms.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

public class AuthDto {

  @Getter
  @Builder
  @AllArgsConstructor
  @NoArgsConstructor
  @ToString
  public static class LoginRequest {

    private String userId;
    private String password;

    public static LoginRequest of(String userId, String password) {
      return LoginRequest.builder()
          .userId(userId)
          .password(password)
          .build();
    }
  }

  @Getter
  @Builder
  @AllArgsConstructor(staticName = "of")
  @NoArgsConstructor
  @ToString
  public static class TokenResponse {

    private String accessToken;
    private String refreshToken;
  }

  @Getter
  @Builder
  @AllArgsConstructor(staticName = "of")
  @NoArgsConstructor
  @ToString
  public static class RefreshTokenRequest {

    private String refreshToken;
  }

  @Getter
  @Builder
  @AllArgsConstructor(staticName = "of")
  @NoArgsConstructor
  @ToString
  public static class RefreshTokenResponse {

    private String accessToken;
  }
}
