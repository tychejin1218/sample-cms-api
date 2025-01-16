package com.sample.cms.config;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Slf4j
@Configuration
public class JasyptConfig {

  @Resource
  Environment environment;

  @Bean
  public StringEncryptor jasyptStringEncryptor() {
    String password = null;
    try {
      password = environment.getRequiredProperty("jasypt.encryptor.key");
    } catch (IllegalStateException e) {
      log.error("required enviroment variable [jasypt.encryptor.password]");
    }

    SimpleStringPBEConfig config = new SimpleStringPBEConfig();
    config.setPassword(password);
    config.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
    config.setKeyObtentionIterations("10000");
    config.setPoolSize("1");
    config.setProviderName("SunJCE");
    config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
    config.setIvGeneratorClassName("org.jasypt.iv.RandomIvGenerator");
    config.setStringOutputType("base64");

    PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
    encryptor.setConfig(config);

    return encryptor;
  }
}
