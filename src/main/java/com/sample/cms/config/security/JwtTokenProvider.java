package com.sample.cms.config.security;

import com.sample.cms.common.component.RedisComponent;
import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.type.ApiStatus;
import com.sample.cms.common.type.RedisKeyType;
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

  private static final String AUTHORIZATION = "Authorization";
  private static final String BEARER = "Bearer";

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

    log.debug("RedisKeyType.REFRESH_TOKEN.getRedisKeyBySubject(subject): {}",
        RedisKeyType.REFRESH_TOKEN.getRedisKeyBySubject(subject));

    // Redis에 Refresh Token 저장
    redisComponent.setStringValue(
        RedisKeyType.REFRESH_TOKEN.getRedisKeyBySubject(subject),
        refreshToken,
        REFRESH_TOKEN_VALID_TIME,
        TimeUnit.MILLISECONDS);

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
   * @param accessToken 검증 대상 액세스 토큰
   * @return 토큰이 유효하면 true 반환
   * @throws ApiException 토큰이 만료되었거나, 유효하지 않으면 예외 발생
   */
  public boolean validateAccessToken(String accessToken) {

    try {

      String subject = getSubject(accessToken);
      String redisToken = redisComponent.getStringValue(
          RedisKeyType.BLACK_LIST.getRedisKeyBySubject(subject));
      if (!accessToken.equals(redisToken)) {
        throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.INVALID_TOKEN);
      }

      Jws<Claims> claims = Jwts.parser()
          .verifyWith(secretKey)
          .build()
          .parseSignedClaims(accessToken);
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
   * @param refreshToken 검증 대상 리프레시 토큰
   * @return 토큰이 유효하다면 true
   * @throws ApiException 토큰이 만료되었거나, 유효하지 않으면 예외 발생
   */
  public boolean validateRefreshToken(String refreshToken) {

    try {

      String subject = getSubject(refreshToken);
      String redisToken = redisComponent.getStringValue(
          RedisKeyType.REFRESH_TOKEN.getRedisKeyBySubject(subject));
      if (!refreshToken.equals(redisToken)) {
        throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.INVALID_TOKEN);
      }

      Jws<Claims> claims = Jwts.parser()
          .verifyWith(secretKey)
          .build()
          .parseSignedClaims(refreshToken);
      return !claims.getPayload().getExpiration().before(new Date());
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
   * @param accessToken 액세스 토큰
   * @return 인증(Authentication) 객체
   */
  public Authentication getAuthentication(String accessToken) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(getSubject(accessToken));
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
      throw new ApiException(HttpStatus.UNAUTHORIZED, ApiStatus.INVALID_REFRESH_TOKEN);
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
   * Access Token을 블랙리스트에 추가
   *
   * @param accessToken 추가할 액세스 토큰
   */
  public void insertBlackList(String accessToken) {

    Claims claims = Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(accessToken)
        .getPayload();

    // 액세스 토큰의 남은 만료 시간 계산
    long remainingExpiration = claims.getExpiration().getTime()
        - System.currentTimeMillis();
    if (remainingExpiration > 0) {
      redisComponent.setStringValue(
          RedisKeyType.BLACK_LIST.getRedisKeyBySubject(claims.getSubject()),
          accessToken,
          remainingExpiration,
          TimeUnit.MILLISECONDS
      );
    }
  }
}
