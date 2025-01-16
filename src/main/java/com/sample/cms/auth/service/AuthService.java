package com.sample.cms.auth.service;

import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import com.sample.cms.config.security.JwtTokenProvider;
import com.sample.cms.domain.entity.CmsUser;
import com.sample.cms.domain.repository.CmsUserRepository;
import java.util.Arrays;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthService {

  private final CmsUserRepository cmsUserRepository;
  private final JwtTokenProvider jwtTokenProvider;

  public AuthDto.LoginResponse authLogin(AuthDto.LoginRequest loginRequest) {

    String userId = loginRequest.getUserId();
    String password = loginRequest.getPassword();

    CmsUser cmsUser = cmsUserRepository.findByUserIdAndPassword(userId, password)
        .orElseThrow(() -> new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.INVALID_REQUEST));

    /*if (!passwordEncoder.matches(signRequest.getPassword(), member.getPassword())) {
      throw new ApiException(ApiStatus.INVALID_REQUEST);
    }*/

    String token = jwtTokenProvider.createToken(
        cmsUser.getUserId(), Arrays.stream(cmsUser.getRoles().split(",")).toList());

    return AuthDto.LoginResponse.of(token);
  }
}
