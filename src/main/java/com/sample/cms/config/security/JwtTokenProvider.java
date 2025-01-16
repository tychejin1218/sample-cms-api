package com.sample.cms.config.security;

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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtTokenProvider {

  private static final long TOKEN_VALID_TIME = 1000L * 60 * 5; // 토큰 유효 시간 5분

  private final UserDetailsService userDetailsService;
  private final SecretKey secretKey;

  public JwtTokenProvider(
      UserDetailsService userDetailsService,
      @Value("${jwt.secret-key}") String secretKey) {
    this.userDetailsService = userDetailsService;
    this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
  }

  /**
   * JWT 토큰 생성
   *
   * @param subject 회원을 식별할 수 있는 유일한 값(Email)
   * @param roles   회원 권한(ROLE_ADMIN, ROLE_USER)
   * @return 생성된 JWT 토큰
   */
  public String createToken(String subject, List<String> roles) {

    Map<String, List<String>> claims = new HashMap<>();
    claims.put("roles", roles);

    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + TOKEN_VALID_TIME);

    return Jwts.builder()
        .subject(subject)
        .claims(claims)
        .issuedAt(now)
        .expiration(expiryDate)
        .signWith(secretKey, SIG.HS256)
        .compact();
  }

  /**
   * Request의 Header에서 JWT 토큰 추출 - Authorization: Bearer JWT 토큰
   *
   * @param request HttpServletRequest 요청 객체
   * @return 추출된 JWT 토큰, 토큰이 없거나 Bearer로 시작하지 않으면 null 반환
   */
  public String getResolveToken(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }

  /**
   * JWT 토큰의 유효성 및 만료일 확인
   *
   * @param token JWT 토큰
   * @return 토큰이 유효한지 여부
   */
  public boolean validateToken(String token) {
    try {
      Jws<Claims> claims = Jwts.parser()
          .verifyWith(secretKey)
          .build()
          .parseSignedClaims(token);
      return !claims.getPayload().getExpiration().before(new Date());
    } catch (ExpiredJwtException e) {
      log.error("Expired Token : {}", e.getMessage());
      throw new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.TOKEN_EXPIRED);
    } catch (JwtException | IllegalArgumentException e) {
      log.error("Invalid Token : {}", e.getMessage());
      throw new ApiException(HttpStatus.BAD_REQUEST, ApiStatus.INVALID_TOKEN);
    }
  }

  /**
   * JWT 토큰으로부터 인증 정보 추출
   *
   * @param token JWT 토큰
   * @return Authentication 추출된 인증 정보
   */
  public Authentication getAuthentication(String token) {
    UserDetails userDetails = userDetailsService.loadUserByUsername(getSubject(token));
    log.debug("userDetails : {}", userDetails);
    return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
  }

  /**
   * JWT 토큰으로부터 subject 추출
   *
   * @param token JWT 토큰
   * @return 추출된 subject (예: Email)
   */
  public String getSubject(String token) {
    return Jwts.parser()
        .verifyWith(secretKey)
        .build()
        .parseSignedClaims(token)
        .getPayload()
        .getSubject();
  }
}
