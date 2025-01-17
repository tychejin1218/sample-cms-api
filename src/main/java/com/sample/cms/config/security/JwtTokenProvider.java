package com.sample.cms.config.security;

import com.sample.cms.common.constants.Constants;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtTokenProvider {

  private static final long ACCESS_TOKEN_VALID_TIME = 1000L * 60 * 5; // 토큰 유효 시간 5분
  private static final long REFRESH_TOKEN_VALID_TIME = 1000L * 60 * 60 * 24 * 7; // 7일

  private final UserDetailsService userDetailsService;
  private final SecretKey secretKey;

  /**
   * JwtTokenProvider 생성자
   *
   * @param userDetailsService 사용자 정보를 로드하기 위한 UserDetailsService
   * @param secretKey          비밀키(Base64URL 인코딩된 문자열)
   */
  public JwtTokenProvider(
      UserDetailsService userDetailsService,
      @Value("${jwt.secret-key}") String secretKey) {
    this.userDetailsService = userDetailsService;
    this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
  }

  /**
   * 액세스 토큰 생성
   *
   * @param subject  사용자를 식별하기 위한 고유 값 (예: UserId)
   * @param roleList 사용자의 권한 목록 (예: ROLE_ADMIN, ROLE_USER)
   * @return 생성된 JWT 액세스 토큰
   */
  public String createAccessToken(String subject, List<String> roleList) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("roleList", roleList);
    return generateToken(subject, claims, ACCESS_TOKEN_VALID_TIME);
  }

  /**
   * 리프레시 토큰 생성
   *
   * @param subject 사용자를 식별하기 위한 고유 값 (예: UserId)
   * @return 생성된 JWT 리프레시 토큰
   */
  public String createRefreshToken(String subject) {
    return generateToken(subject, new HashMap<>(), REFRESH_TOKEN_VALID_TIME);
  }

  /**
   * JWT 토큰 생성
   *
   * @param subject   사용자를 식별하기 위한 고유 값
   * @param claims    추가 클레임 정보
   * @param validTime 토큰 유효 시간 (ms 단위)
   * @return 생성된 JWT 토큰
   */
  private String generateToken(String subject, Map<String, ?> claims, long validTime) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + validTime);
    return Jwts.builder()
        .subject(subject)
        .claims(claims)
        .issuedAt(now)
        .expiration(expiryDate)
        .signWith(secretKey, SIG.HS256)
        .compact();
  }

  /**
   * HTTP 요청의 Header에서 JWT 액세스 토큰 추출
   *
   * <p>"Authorization" 헤더에서 "Bearer "로 시작하는 JWT 토큰을 추출</p>
   *
   * @param request HttpServletRequest 요청 객체
   * @return 추출된 JWT 토큰. 토큰이 없거나 Bearer로 시작하지 않으면 null 반환
   */
  public String getResolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader(Constants.AUTHORIZATION);
    if (bearerToken != null && bearerToken.startsWith(Constants.BEARER + " ")) {
      return bearerToken.substring(7);
    }
    return null;
  }

  /**
   * 액세스 토큰의 유효성을 확인합니다.
   *
   * @param token 액세스 토큰
   * @return 토큰이 유효하다면 true
   * @throws ApiException 토큰이 만료되었거나, 잘못된 경우
   */
  public boolean validateAccessToken(String token) {
    try {
      Jws<Claims> claims = Jwts.parser()
          .verifyWith(secretKey)
          .build()
          .parseSignedClaims(token);
      return !claims.getPayload().getExpiration().before(new Date());
    } catch (ExpiredJwtException e) {
      log.error("Expired Token : {}", e.getMessage());
      throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.TOKEN_EXPIRED);
    } catch (JwtException | IllegalArgumentException e) {
      log.error("Invalid Token : {}", e.getMessage());
      throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.INVALID_TOKEN);
    }
  }

  /**
   * 리프레시 토큰의 유효성을 확인
   *
   * @param token 리프레시 토큰
   * @return 토큰이 유효하다면 true
   * @throws ApiException 토큰이 만료되었거나, 잘못된 경우
   */
  public boolean validateRefreshToken(String token) {
    try {
      Jwts.parser()
          .verifyWith(secretKey)
          .build()
          .parseSignedClaims(token);
      return true;
    } catch (ExpiredJwtException e) {
      log.error("Expired Refresh Token: {}", e.getMessage());
      throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.REFRESH_TOKEN_EXPIRED);
    } catch (JwtException | IllegalArgumentException e) {
      log.error("Invalid Refresh Token: {}", e.getMessage());
      throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.INVALID_REFRESH_TOKEN);
    }
  }

  /**
   * 액세스 토큰으로부터 Spring Security Authentication 객체를 제공
   *
   * @param token 액세스 토큰
   * @return 인증(Authentication) 객체
   */
  public Authentication getAuthentication(String token) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(getSubject(token));
    log.debug("userDetails: {}", userDetails);
    return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
  }

  /**
   * JWT 토큰에서 subject(사용자 식별자)를 추출
   *
   * @param token JWT 토큰 (액세스 토큰 또는 리프레시 토큰)
   * @return 추출된 subject (예: userId)
   */
  public String getSubject(String token) {
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getSubject();
  }

  /**
   * 리프레시 토큰을 통해 새로운 액세스 토큰을 생성
   *
   * @param refreshToken 유효한 리프레시 토큰
   * @return 새로 생성된 액세스 토큰
   * @throws ApiException 리프레시 토큰이 유효하지 않은 경우
   */
  public String reissueAccessToken(String refreshToken) {

    if (!validateRefreshToken(refreshToken)) {
      throw new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.INVALID_REFRESH_TOKEN);
    }

    String subject = getSubject(refreshToken);
    UserDetails userDetails = userDetailsService.loadUserByUsername(subject);

    // 기존 권한 정보에서 역할(role) 추출
    List<String> roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();

    // 새로운 액세스 토큰 생성
    return createAccessToken(subject, roles);
  }
}
