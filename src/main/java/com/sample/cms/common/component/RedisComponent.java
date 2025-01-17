package com.sample.cms.common.component;

import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

@Slf4j
@RequiredArgsConstructor
@Component
public class RedisComponent {

  private final StringRedisTemplate stringRedisTemplate;
  private final RedisTemplate<String, Object> objectRedisTemplate;
  private final RedisTemplate<String, Integer> integerRedisTemplate;

  /**
   * 키에 해당하는 문자열을 저장
   *
   * @param key      저장할 키
   * @param value    저장할 값
   * @param duration 지속시간
   * @param timeunit 지속시간의 단위
   */
  public void setStringValue(String key, String value, long duration, TimeUnit timeunit) {
    try {
      ValueOperations<String, String> valueOperations = stringRedisTemplate.opsForValue();
      valueOperations.set(key, value, duration, timeunit);
    } catch (Exception e) {
      log.error("setStringValue key: {}", key, e);
    }
  }

  /**
   * 키에 해당하는 문자열을 조회
   *
   * @param key 검색할 키
   * @return 해당 키로부터 가져온 값, 없거나 오류가 발생하면 null 반환
   */
  public String getStringValue(String key) {
    try {
      ValueOperations<String, String> valueOperations = stringRedisTemplate.opsForValue();
      String value = valueOperations.get(key);
      if (StringUtils.isNotBlank(value)) {
        return value;
      }
    } catch (Exception e) {
      log.error("getStringValue key: {}", key, e);
    }
    return null;
  }

  /**
   * 키에 해당하는 객체를 JSON 문자열 형태로 저장
   *
   * @param key      저장할 키
   * @param value    저장할 객체
   * @param duration 지속시간
   * @param timeunit 지속시간의 단위
   */
  public void setObjectValue(String key, Object value, long duration, TimeUnit timeunit) {
    try {
      ValueOperations<String, Object> valueOperations = objectRedisTemplate.opsForValue();
      valueOperations.set(key, value, duration, timeunit);
    } catch (Exception e) {
      log.error("setObjectValue key: {}", key, e);
    }
  }

  /**
   * 키에 해당하는 JSON 문자열을 조회하여 객체로 반환
   *
   * @param key   검색할 키
   * @param clazz 반환할 객체의 클래스 타입
   * @param <T>   반환하는 객체의 타입
   * @return 해당 키로부터 가져온 객체, 없거나 오류가 발생하면 null 반환
   */
  public <T> T getObjectValue(String key, Class<T> clazz) {
    try {
      ValueOperations<String, Object> valueOperations = objectRedisTemplate.opsForValue();
      Object result = valueOperations.get(key);
      if (clazz.isInstance(result)) {
        return clazz.cast(result);
      }
    } catch (Exception e) {
      log.error("getObjectValue key: {}", key, e);
    }
    return null;
  }

  /**
   * 키에 해당하는 정수를 저장
   *
   * @param key      저장할 키
   * @param value    저장할 정수
   * @param duration 지속시간
   * @param timeunit 지속시간의 단위
   */
  public void setIntegerValue(String key, Integer value, long duration, TimeUnit timeunit) {
    try {
      ValueOperations<String, Integer> valueOperations = integerRedisTemplate.opsForValue();
      valueOperations.set(key, value, duration, timeunit);
    } catch (Exception e) {
      log.error("setIntegerValue key: {}", key, e);
    }
  }

  /**
   * 키에 해당하는 정수를 조회
   *
   * @param key 검색할 키
   * @return 해당 키로부터 가져온 정수 값, 없거나 오류가 발생하면 null 반환
   */
  public Integer getIntegerValue(String key) {
    try {
      ValueOperations<String, Integer> valueOperations = integerRedisTemplate.opsForValue();
      return valueOperations.get(key);
    } catch (Exception e) {
      log.error("getIntegerValue key: {}", key, e);
    }
    return null;
  }

  /**
   * 키에 해당하는 값을 삭제
   *
   * @param key 삭제할 키
   * @return 삭제가 성공했는지 여부
   */
  public boolean deleteKey(String key) {
    try {
      return Boolean.TRUE.equals(stringRedisTemplate.delete(key));
    } catch (Exception e) {
      log.error("deleteKey key : {}", key, e);
      return false;
    }
  }
}
