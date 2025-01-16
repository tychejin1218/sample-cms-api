package com.sample.cms.common.reponse;

import com.sample.cms.common.type.ApiStatus;
import java.util.Date;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateFormatUtils;

@Getter
@Setter
public class ErrorResponse {

  private String statusCode;
  private String message;
  private String method;
  private String path;
  private String timestamp;

  @Builder
  ErrorResponse(
      String statusCode,
      String message,
      String method,
      String path,
      String timestamp
  ) {
    this.statusCode = statusCode;
    this.message =
        StringUtils.isNotBlank(message) ? message
            : ApiStatus.getByCode(statusCode).getMessage();
    this.method = method;
    this.path = path;
    this.timestamp =
        StringUtils.isNotBlank(timestamp) ? timestamp
            : DateFormatUtils.format(new Date(), "yyyyMMddHHMMSS");
  }
}
