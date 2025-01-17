package com.sample.cms.config;

import io.lettuce.core.ReadFrom;
import io.lettuce.core.cluster.ClusterClientOptions;
import io.lettuce.core.cluster.ClusterTopologyRefreshOptions;
import java.time.Duration;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisClusterConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializer;

@Configuration
public class RedisConfig {

  @Value("${redis.cluster.nodes}")
  private List<String> nodes;

  /**
   * 클러스터 구성 및 클라이언트 설정을 포함한 LettuceConnectionFactory 빈을 생성
   *
   * @return LettuceConnectionFactory 객체
   */
  @Bean
  public LettuceConnectionFactory lettuceConnectionFactory() {

    RedisClusterConfiguration clusterConfig = new RedisClusterConfiguration(nodes);

    ClusterTopologyRefreshOptions topologyRefreshOptions = ClusterTopologyRefreshOptions.builder()
        .dynamicRefreshSources(true)
        // 클러스터 토폴로지를 60초마다 주기적으로 갱신하도록 설정
        .enablePeriodicRefresh(Duration.ofSeconds(60))
        // 연결 오류, 시간 초과 등 즉각적으로 클러스터 토플로지를 갱신하도록 설정
        .enableAllAdaptiveRefreshTriggers()
        // 갱신 타임아웃을 30초로 설정
        .adaptiveRefreshTriggersTimeout(Duration.ofSeconds(30))
        .build();

    ClusterClientOptions clientOptions = ClusterClientOptions.builder()
        .autoReconnect(true)
        .topologyRefreshOptions(topologyRefreshOptions)
        .build();

    LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
        .clientOptions(clientOptions)
        // 읽기 작업을 우선적으로 수행하도록 설정
        .readFrom(ReadFrom.REPLICA_PREFERRED)
        .build();

    return new LettuceConnectionFactory(clusterConfig, clientConfig);
  }

  /**
   * 문자열을 저장하기 위한 StringRedisTemplate 빈을 생성
   *
   * @param lettuceConnectionFactory Lettuce를 통한 Redis 연결 팩토리
   * @return StringRedisTemplate 객체
   */
  @Bean
  public StringRedisTemplate stringRedisTemplate(
      LettuceConnectionFactory lettuceConnectionFactory) {
    return new StringRedisTemplate(lettuceConnectionFactory);
  }

  /**
   * 객체를 저장하기 위한 RedisTemplate 빈을 생성
   *
   * @param lettuceConnectionFactory Lettuce를 통한 Redis 연결 팩토리
   * @return RedisTemplate 객체
   */
  @Bean
  public RedisTemplate<String, Object> objectRedisTemplate(
      LettuceConnectionFactory lettuceConnectionFactory) {
    RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
    redisTemplate.setConnectionFactory(lettuceConnectionFactory);
    redisTemplate.setKeySerializer(RedisSerializer.string());
    redisTemplate.setHashKeySerializer(RedisSerializer.string());
    redisTemplate.setDefaultSerializer(RedisSerializer.json());
    redisTemplate.setValueSerializer(RedisSerializer.json());
    redisTemplate.setHashValueSerializer(RedisSerializer.json());
    return redisTemplate;
  }

  /**
   * 정수를 저장하기 위한 RedisTemplate 빈을 생성
   *
   * @param lettuceConnectionFactory Lettuce를 통한 Redis 연결 팩토리
   * @return RedisTemplate 객체
   */
  @Bean
  public RedisTemplate<String, Integer> integerRedisTemplate(
      LettuceConnectionFactory lettuceConnectionFactory) {
    RedisTemplate<String, Integer> template = new RedisTemplate<>();
    template.setConnectionFactory(lettuceConnectionFactory);
    template.setKeySerializer(RedisSerializer.string());
    template.setValueSerializer(RedisSerializer.json());
    return template;
  }
}
