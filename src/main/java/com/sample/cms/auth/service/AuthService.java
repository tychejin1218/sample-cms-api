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

  /**
   * 로그인 요청을 처리하고 엑세스 토큰 및 리프레시 토큰을 생성하여 반환
   *
   * @param loginRequest 로그인 요청 정보 (사용자 ID, 비밀번호 포함)
   * @return 액세스 토큰 및 리프레시 토큰를 반환
   */
  public AuthDto.TokenResponse getTokenByLogin(AuthDto.LoginRequest loginRequest) {

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

    // 토큰 생성
    String accessToken = jwtTokenProvider.createToken(cmsUser.getUserId(), roleList);
    String refreshToken = jwtTokenProvider.createRefreshToken(userId);

    return AuthDto.TokenResponse.of(accessToken, refreshToken);
  }

  /**
   * 리프레시 토큰을 통해 새로운 액세스 토큰을 발급
   *
   * @param refreshTokenRequest 리프레시 토큰 요청 정보
   * @return 새로 발급된 액세스 토큰 정보를 반환
   */
  public AuthDto.RefreshTokenResponse getAccessTokenByRefreshToken(
      AuthDto.RefreshTokenRequest refreshTokenRequest) {
    String accessToken = jwtTokenProvider.reissueAccessToken(refreshTokenRequest.getRefreshToken());
    return AuthDto.RefreshTokenResponse.of(accessToken);
  }
}
