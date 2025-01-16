package com.sample.cms.common.reponse;

import com.sample.cms.common.type.ApiStatus;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpStatus;

@SuppressWarnings("PMD.ImmutableField")
@Getter
@NoArgsConstructor
public class BaseResponse<T> {

  private String statusCode;
  private String message;
  private T data;

  /**
   * Builder 패턴을 통해 객체 생성
   *
   * @param statusCode 상태 코드
   * @param message    상태 메시지
   * @param data       데이터
   */
  @Builder
  public BaseResponse(String statusCode, String message, T data) {
    this.statusCode = StringUtils.defaultIfBlank(statusCode, "200");
    this.message = StringUtils.defaultIfBlank(message,
        ApiStatus.getByCode(this.statusCode).getMessage());
    this.data = data;
  }

  /**
   * 상태 코드와 메시지 초기화
   *
   * @param status HttpStatus 상태
   */
  public BaseResponse(HttpStatus status) {
    this.statusCode = String.valueOf(status.value());
    this.message = ApiStatus.getByCode(this.statusCode).getMessage();
  }

  /**
   * 성공 응답을 생성
   *
   * @param body 응답 데이터
   * @param <T>  데이터 타입
   * @return BaseResponse 객체
   */
  public static <T> BaseResponse<T> ok(T body) {
    return BaseResponse.<T>builder()
        .statusCode("200")
        .data(body)
        .message(ApiStatus.getByCode("200").getMessage())
        .build();
  }

  /**
   * 메시지 설정 후 현재 객체 반환
   *
   * @param message 상태 메시지
   * @return 현재의 BaseResponse 객체
   */
  public BaseResponse<T> withMessage(String message) {
    return BaseResponse.<T>builder()
        .statusCode(this.statusCode)
        .data(this.data)
        .message(message).build();
  }

  /**
   * 상태 코드 설정 후 현재 객체 반환
   *
   * @param statusCode 상태 코드
   * @return 현재의 BaseResponse 객체
   */
  public BaseResponse<T> withStatusCode(String statusCode) {
    return BaseResponse.<T>builder()
        .statusCode(statusCode)
        .data(this.data)
        .message(this.message).build();
  }
}
