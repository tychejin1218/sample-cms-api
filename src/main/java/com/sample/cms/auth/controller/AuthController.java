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

  @PostMapping("/auth/login")
  public BaseResponse<AuthDto.LoginResponse> authLogin(
      @RequestBody AuthDto.LoginRequest loginRequest) {
    return BaseResponse.ok(authService.authLogin(loginRequest));
  }
}
