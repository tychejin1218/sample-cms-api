package com.sample.cms.auth.service;

import com.sample.cms.auth.dto.AuthDto;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import com.sample.cms.config.security.JwtTokenProvider;
import com.sample.cms.domain.entity.CmsUser;
import com.sample.cms.domain.repository.CmsUserRepository;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthService {

  private final CmsUserRepository cmsUserRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtTokenProvider jwtTokenProvider;

  public AuthDto.LoginResponse authLogin(AuthDto.LoginRequest loginRequest) {

    String userId = loginRequest.getUserId();

    // 사용자 검증
    CmsUser cmsUser = cmsUserRepository.findByUserId(userId)
        .orElseThrow(() -> {
          log.error("로그인 실패: 존재하지 않는 사용자 ID: {}", userId);
          return new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.INVALID_CREDENTIALS);
        });

    // 비밀번호 검증
    if (!passwordEncoder.matches(loginRequest.getPassword(), cmsUser.getPassword())) {
      log.warn("로그인 실패: 비밀번호 불일치 (사용자 ID: {})", userId);
      throw new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.INVALID_CREDENTIALS);
    }

    // 권한 문자열을 리스트로 변환
    List<String> roleList = Arrays.stream(cmsUser.getRoles().split(","))
        .map(String::trim)
        .toList();

    // JWT 토큰 생성
    String token = jwtTokenProvider.createToken(cmsUser.getUserId(), roleList);

    return AuthDto.LoginResponse.of(token);
  }
}
