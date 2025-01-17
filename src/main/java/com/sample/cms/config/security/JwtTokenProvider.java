package com.sample.cms.config.security;

import com.sample.cms.common.component.RedisComponent;
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
import java.util.concurrent.TimeUnit;
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

  private static final long ACCESS_TOKEN_VALID_TIME = 1000L * 60 * 60 * 2;        // 2시간
  private static final long REFRESH_TOKEN_VALID_TIME = 1000L * 60 * 60 * 24 * 7;  // 7일

  public static final String REFRESH_TOKEN = "REFRESH_TOKEN";

  public static final String AUTHORIZATION = "Authorization";
  public static final String BEARER = "Bearer";

  private final UserDetailsService userDetailsService;
  private final RedisComponent redisComponent;
  private final SecretKey secretKey;

  /**
   * JwtTokenProvider 생성자
   *
   * @param userDetailsService 사용자 정보를 로드하기 위한 UserDetailsService
   * @param redisComponent     Redis 연동을 위한 컴포넌트
   * @param secretKey          JWT 서명을 위한 시크릿 키 (Base64 인코딩된 문자열)
   */
  public JwtTokenProvider(
      UserDetailsService userDetailsService,
      RedisComponent redisComponent,
      @Value("${jwt.secret-key}") String secretKey) {
    this.userDetailsService = userDetailsService;
    this.redisComponent = redisComponent;
    this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
  }

  /**
   * 액세스 토큰(Access Token)을 생성
   *
   * @param subject  사용자 고유 식별 값 (예: userId)
   * @param roleList 사용자의 역할(roles) 목록
   * @return 생성된 액세스 토큰 문자열
   */
  public String createAccessToken(String subject, List<String> roleList) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("roleList", roleList);
    return generateToken(subject, claims, ACCESS_TOKEN_VALID_TIME);
  }

  /**
   * 리프레시 토큰(Refresh Token)을 생성하고 Redis에 저장
   *
   * @param subject 사용자 고유 식별 값 (예: userId)
   * @return 생성된 리프레시 토큰 문자열
   */
  public String createRefreshToken(String subject) {

    String refreshToken = generateToken(subject, new HashMap<>(), REFRESH_TOKEN_VALID_TIME);

    // Redis에 Refresh Token 저장
    redisComponent.setStringValue(subject + ":" + REFRESH_TOKEN, refreshToken,
        REFRESH_TOKEN_VALID_TIME, TimeUnit.MILLISECONDS);

    return refreshToken;
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
   * HTTP 요청의 헤더에서 JWT 토큰 추출
   *
   * <p>"Authorization" 헤더에서 "Bearer "로 시작하는 JWT 토큰을 추출</p>
   *
   * @param request HttpServletRequest 요청 객체
   * @return 추출된 JWT 토큰. 토큰이 없거나 Bearer로 시작하지 않으면 null 반환
   */
  public String getResolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader(AUTHORIZATION);
    if (bearerToken != null && bearerToken.startsWith(BEARER + " ")) {
      return bearerToken.substring(7);
    }
    return null;
  }

  /**
   * 액세스 토큰의 유효성을 확인
   *
   * @param token 검증 대상 액세스 토큰
   * @return 토큰이 유효하면 true 반환
   * @throws ApiException 토큰이 만료되었거나, 유효하지 않으면 예외 발생
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
   * @param token 검증 대상 리프레시 토큰
   * @return 토큰이 유효하다면 true
   * @throws ApiException 토큰이 만료되었거나, 유효하지 않으면 예외 발생
   */
  public boolean validateRefreshToken(String token) {

    try {

      String subject = getSubject(token);
      String redisToken = redisComponent.getStringValue(subject + ":" + REFRESH_TOKEN);
      if (!token.equals(redisToken)) {
        throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.INVALID_TOKEN);
      }

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
   * 리프레시 토큰을 검증하고 새로운 액세스 토큰을 생성
   *
   * @param refreshToken 발급 기준이 되는 리프레시 토큰
   * @return 새로 생성된 액세스 토큰
   * @throws ApiException 리프레시 토큰이 유효하지 않은 경우 예외 발생
   */
  public String getAccessToken(String refreshToken) {

    if (!validateRefreshToken(refreshToken)) {
      throw new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.INVALID_REFRESH_TOKEN);
    }

    String subject = getSubject(refreshToken);
    UserDetails userDetails = userDetailsService.loadUserByUsername(subject);

    // 권한 목록 추출
    List<String> roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .toList();

    // 새로운 액세스 토큰 생성
    return createAccessToken(subject, roles);
  }

  /**
   * Redis에서 토큰을 삭제
   *
   * @param subject 사용자 고유 식별 값 (예: userId)
   * @return 토큰 삭제 성공 여부
   */
  public boolean deleteToken(String subject) {
    return redisComponent.deleteKey(subject + ":" + REFRESH_TOKEN);
  }
}
