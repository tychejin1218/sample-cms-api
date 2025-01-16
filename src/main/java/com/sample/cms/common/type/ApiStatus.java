package com.sample.cms.common.type;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum ApiStatus {

  OK("200", "성공"),

  // Custom Exception 에러 코드
  CUSTOM_EXCEPTION("800", "오류가 발생했습니다. 확인 후 다시 시도해주세요."),
  INVALID_REQUEST("801", "유효하지 않은 요청입니다."),
  FORBIDDEN_REQUEST("802", "허용되지 않은 요청입니다."),
  DUPLICATED_REQUEST("803", "중복된 요청입니다."),
  NOT_FOUND("804", "존재하지 않는 정보입니다."),
  INVALID_CREDENTIALS("805", "아이디나 비밀번호가 올바르지 않습니다."),
  UNAUTHORIZED("806", "유효하지 않은 권한입니다."),
  TOKEN_EXPIRED("807", "토큰이 만료되었습니다."),
  INVALID_SIGNATURE("808", "토큰 서명이 유효하지 않습니다."),
  INVALID_TOKEN("809", "유효하지 않은 토큰입니다."),

  // Exception Handler 에러 코드
  INTERNAL_SERVER_ERROR("900", "내부 오류가 발생했습니다. 확인 후 다시 시도해주세요."),
  METHOD_ARGUMENT_NOT_VALID("901", "파라미터가 유효하지 않습니다."),
  MISSING_SERVLET_REQUEST_PARAMETER("902", "필수 파라미터가 누락되었습니다."),
  CONSTRAINT_VIOLATION("903", "파라미터 유효성 검사에 실패했습니다."),
  METHOD_ARGUMENT_TYPE_MISMATCH("904", "파라미터 타입이 올바르지 않습니다."),
  NO_HANDLER_FOUND("905", "요청한 URL을 찾을 수 없습니다."),
  HTTP_REQUEST_METHOD_NOT_SUPPORTED("906", "지원하지 않는 메서드입니다."),
  HTTP_MEDIA_TYPE_NOT_SUPPORTED("907", "지원되지 않는 미디어 타입입니다."),
  HTTP_MESSAGE_NOT_READABLE_EXCEPTION("908", "읽을 수 있는 요청 정보가 없습니다.");

  private final String code;
  private final String message;

  private static final Map<String, ApiStatus> BY_STATUS_CODE =
      Stream.of(values())
          .collect(Collectors.toMap(ApiStatus::getCode, Function.identity()));

  public static ApiStatus getByCode(String code) {
    return BY_STATUS_CODE.get(code);
  }
}
