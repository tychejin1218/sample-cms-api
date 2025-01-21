package com.sample.cms.auth.controller;

import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.auth.service.AuthService;
import com.sample.cms.common.reponse.BaseResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
public class AuthController {

  private final AuthService authService;

  /**
   * 로그인 요청을 처리하고 엑세스 토큰 및 리프레시 토큰을 생성하여 반환
   *
   * @param loginRequest 로그인 요청 정보 (사용자 ID, 비밀번호 포함)
   * @return 액세스 토큰 및 리프레시 토큰를 반환
   */
  @PostMapping("/auth/login")
  public BaseResponse<AuthDto.LoginResponse> getTokenByLogin(
      @RequestBody AuthDto.LoginRequest loginRequest) {
    return BaseResponse.ok(authService.getTokenByLogin(loginRequest));
  }

  /**
   * 리프레시 토큰을 통해 새로운 액세스 토큰을 발급
   *
   * @param refreshTokenRequest 리프레시 토큰 요청 정보
   * @return 새로 발급된 액세스 토큰 정보를 반환
   */
  @PostMapping("/auth/refresh-token")
  public BaseResponse<AuthDto.RefreshTokenResponse> getAccessTokenByRefreshToken(
      @RequestBody AuthDto.RefreshTokenRequest refreshTokenRequest) {
    return BaseResponse.ok(authService.getAccessTokenByRefreshToken(refreshTokenRequest));
  }

  /**
   * 로그아웃 요청을 처리하고, Refresh Token을 삭제 및 Access Token을 블랙리스트 처리
   *
   * @param logoutRequest 로그아웃 요청 정보
   * @return 사용자 ID
   */
  @PostMapping("/auth/logout")
  public BaseResponse<AuthDto.LogoutResponse> deleteTokenByLogout(
      @RequestBody AuthDto.LogoutRequest logoutRequest) {
    return BaseResponse.ok(authService.deleteTokenByLogout(logoutRequest));
  }
}
