package com.sample.cms.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sample.cms.common.reponse.ErrorResponse;
import com.sample.cms.common.type.ApiStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

  @Override
  public void handle(
      HttpServletRequest request,
      HttpServletResponse response,
      AccessDeniedException accessDeniedException)
      throws IOException {
    log.error("No Authorization Request URI: {}", request.getRequestURI(), accessDeniedException);
    ObjectMapper objectMapper = new ObjectMapper();
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setCharacterEncoding("UTF-8");
    objectMapper.writeValue(response.getWriter(), ErrorResponse.builder()
        .statusCode(ApiStatus.UNAUTHORIZED.getCode())
        .method(request.getMethod())
        .message(ApiStatus.UNAUTHORIZED.getMessage())
        .path(request.getRequestURI())
        .build());
  }
}
