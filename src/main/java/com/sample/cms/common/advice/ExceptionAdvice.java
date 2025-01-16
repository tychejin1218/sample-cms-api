package com.sample.cms.common.advice;


import com.sample.cms.common.exception.ApiException;
import com.sample.cms.common.reponse.ErrorResponse;
import com.sample.cms.common.type.ApiStatus;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.util.ObjectUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

/**
 * 공통 예외 처리 핸들러
 */
@Slf4j
@RestControllerAdvice
public class ExceptionAdvice {

  private static final String EXCEPTION = "Exception";

  /**
   * 일반 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 예외
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(Exception.class)
  public ResponseEntity<ErrorResponse> handleException(
      HttpServletRequest request,
      Exception e) {
    log.error("handleException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.INTERNAL_SERVER_ERROR.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 커스텀 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 ApiException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(ApiException.class)
  public ResponseEntity<ErrorResponse> handleApiException(
      HttpServletRequest request,
      ApiException e) {
    log.error("handleApiException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
        ErrorResponse.builder()
            .statusCode(e.getStatus().getCode())
            .method(request.getMethod())
            .message(e.getMessage())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 접근 거부 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 AccessDeniedException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ErrorResponse> handleAccessDeniedException(
      HttpServletRequest request,
      AccessDeniedException e) {
    log.error("handleAccessDeniedException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.FORBIDDEN_REQUEST.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 메서드 인자 유효성 검사 실패 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 MethodArgumentNotValidException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(
      HttpServletRequest request,
      MethodArgumentNotValidException e) {
    log.error("handleMethodArgumentNotValidException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);

    String message = "";

    List<String> messages = new ArrayList<>();
    BindingResult bindingResult = e.getBindingResult();
    for (ObjectError error : bindingResult.getGlobalErrors()) {
      messages.add(error.getObjectName() + ":" + error.getDefaultMessage());
    }

    for (FieldError error : bindingResult.getFieldErrors()) {
      messages.add(error.getField() + ":" + error.getDefaultMessage());
    }

    if (!ObjectUtils.isEmpty(messages)) {
      message = String.join(", ", messages);
    }

    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.METHOD_ARGUMENT_NOT_VALID.getCode())
            .message(message)
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 서블릿 요청 파라미터 누락 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 MissingServletRequestParameterException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<ErrorResponse> handleMissingServletRequestParameterException(
      HttpServletRequest request,
      MissingServletRequestParameterException e) {
    log.error("handleMissingServletRequestParameterException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.MISSING_SERVLET_REQUEST_PARAMETER.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 제약 조건 위반 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 ConstraintViolationException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(ConstraintViolationException.class)
  public ResponseEntity<ErrorResponse> handleConstraintViolationException(
      HttpServletRequest request,
      ConstraintViolationException e) {
    log.error("handleConstraintViolationException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.CONSTRAINT_VIOLATION.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 메서드 인자 타입 불일치 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 MethodArgumentTypeMismatchException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ErrorResponse> handleMethodArgumentTypeMismatchException(
      HttpServletRequest request,
      MethodArgumentTypeMismatchException e) {
    log.error("handleMethodArgumentTypeMismatchException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.METHOD_ARGUMENT_TYPE_MISMATCH.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 핸들러를 찾을 수 없는 경우 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 NoHandlerFoundException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(NoHandlerFoundException.class)
  public ResponseEntity<ErrorResponse> handleNoHandlerFoundException(
      HttpServletRequest request,
      NoHandlerFoundException e) {
    log.error("handleNoHandlerFoundException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.NO_HANDLER_FOUND.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * HTTP 요청 메서드가 지원되지 않는 경우 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 HttpRequestMethodNotSupportedException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ErrorResponse> handleHttpRequestMethodNotSupportedException(
      HttpServletRequest request,
      HttpRequestMethodNotSupportedException e) {
    log.error("handleHttpRequestMethodNotSupportedException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.HTTP_REQUEST_METHOD_NOT_SUPPORTED.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 지원되지 않는 미디어 타입 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 HttpMediaTypeNotSupportedException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
  public ResponseEntity<ErrorResponse> handleHttpMediaTypeNotSupportedException(
      HttpServletRequest request,
      HttpMediaTypeNotSupportedException e) {
    log.error("handleHttpMediaTypeNotSupportedException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.HTTP_MEDIA_TYPE_NOT_SUPPORTED.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }

  /**
   * 읽을 수 없는 HTTP 메시지 예외 처리
   *
   * @param request HTTP 요청 객체
   * @param e       발생한 HttpMessageNotReadableException
   * @return ResponseEntity 에러 응답 객체
   */
  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException(
      HttpServletRequest request,
      HttpMessageNotReadableException e) {
    log.error("handleHttpMessageNotReadableException : {}", request.getRequestURI(), e);
    request.setAttribute(EXCEPTION, true);
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
        ErrorResponse.builder()
            .statusCode(ApiStatus.HTTP_MESSAGE_NOT_READABLE_EXCEPTION.getCode())
            .method(request.getMethod())
            .path(request.getRequestURI())
            .build()
    );
  }
}
