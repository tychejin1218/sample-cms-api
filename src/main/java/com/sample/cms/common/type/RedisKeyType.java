package com.sample.cms.common.type;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum RedisKeyType {

  REFRESH_TOKEN("CMS:REFRESH_TOKEN"),
  BLACK_LIST("CMS:BLACK_LIST");

  private final String redisKey;

  /**
   * subject를 기준으로 Redis 키를 생성
   *
   * @param subject JWT 토큰에서 추출된 subject (예: userId)
   * @return Redis 키 (예: CMS:REFRESH_TOKEN:admin01)
   */
  public String getRedisKeyBySubject(String subject) {
    return this.redisKey + ":" + subject;
  }
}
