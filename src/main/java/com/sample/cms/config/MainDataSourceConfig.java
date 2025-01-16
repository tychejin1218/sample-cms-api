package com.sample.cms.config;

import com.querydsl.jpa.impl.JPAQueryFactory;
import com.sample.cms.common.constants.Constants;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.type.Alias;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.JpaProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.boot.orm.jpa.EntityManagerFactoryBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.LazyConnectionDataSourceProxy;
import org.springframework.jdbc.datasource.lookup.AbstractRoutingDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Main 데이터 소스 설정 클래스
 *
 * <p>다중 데이터 소스 (읽기/쓰기 전용)를 설정하고 관리하는 구성 클래스</p>
 */
@Slf4j
@AllArgsConstructor
@EnableAutoConfiguration(exclude = {DataSourceAutoConfiguration.class})
@EnableTransactionManagement
@MapperScan(annotationClass = Mapper.class,
    basePackages = MainDataSourceConfig.MYBATIS_MAPPER_PACKAGES,
    sqlSessionFactoryRef = MainDataSourceConfig.DATASOURCE_PREFIX + "SessionFactory")
@EnableJpaRepositories(
    basePackages = MainDataSourceConfig.JPA_REPOSITORY_PACKAGES,
    entityManagerFactoryRef = MainDataSourceConfig.DATASOURCE_PREFIX + "EntityManagerFactory",
    transactionManagerRef = MainDataSourceConfig.DATASOURCE_PREFIX + "TransactionManager"
)
@EnableJpaAuditing
@Configuration
public class MainDataSourceConfig {

  public static final String DATASOURCE_PREFIX = "main";
  public static final String DATASOURCE_BEAN_NAME = "DataSource";
  private static final String DATASOURCE_PROPERTY_PREFIX = "main.datasource";
  public static final String MYBATIS_MAPPER_PACKAGES = Constants.BASE_PACKAGE + ".**.mapper";
  private static final String[] JPA_ENTITY_PACKAGES = {Constants.BASE_PACKAGE + ".**.entity"};
  public static final String JPA_REPOSITORY_PACKAGES = Constants.BASE_PACKAGE + ".**.repository";

  /**
   * 단일 데이터베이스 구성을 위한 데이터 소스 빈을 설정
   *
   * @return DataSource
   */
  @Profile("main_db_single")
  @Primary
  @ConfigurationProperties(prefix = DATASOURCE_PROPERTY_PREFIX + ".single")
  @Bean(DATASOURCE_PREFIX + DATASOURCE_BEAN_NAME)
  public DataSource dataSource() {
    return DataSourceBuilder.create().type(HikariDataSource.class).build();
  }

  /**
   * 데이터베이스 리플리케이션 설정을 위한 내부 클래스
   */
  @Profile("main_db_replication")
  @Configuration
  class ReplicationConfig {

    /**
     * 쓰기 전용 데이터 소스를 설정
     *
     * @return DataSource
     */
    @ConfigurationProperties(prefix = DATASOURCE_PROPERTY_PREFIX + ".writer")
    @Bean(DATASOURCE_PREFIX + "WriterDataSource")
    public DataSource writerDataSource() {
      return DataSourceBuilder.create().type(HikariDataSource.class).build();
    }

    /**
     * 읽기 전용 데이터 소스를 설정
     *
     * @return DataSource
     */
    @Primary
    @ConfigurationProperties(prefix = DATASOURCE_PROPERTY_PREFIX + ".reader")
    @Bean(DATASOURCE_PREFIX + "ReaderDataSource")
    public DataSource readerDataSource() {
      return DataSourceBuilder.create().type(HikariDataSource.class).build();
    }

    /**
     * 다중 데이터 소스를 설정
     *
     * @param writerDataSource 쓰기 전용 데이터 소스
     * @param readerDataSource 읽기 전용 데이터 소스
     * @return DataSource
     */
    @Primary
    @Bean(DATASOURCE_PREFIX + "RoutingDatasource")
    public DataSource routingDataSource(
        @Qualifier(DATASOURCE_PREFIX + "WriterDataSource") DataSource writerDataSource,
        @Qualifier(DATASOURCE_PREFIX + "ReaderDataSource") DataSource readerDataSource) {

      final String writerKey = "writerKey";
      final String readerKey = "readerKey";
      AbstractRoutingDataSource routingDataSource = new AbstractRoutingDataSource() {
        @Override
        protected Object determineCurrentLookupKey() {
          return TransactionSynchronizationManager.isCurrentTransactionReadOnly()
              ? readerKey : writerKey;
        }
      };

      Map<Object, Object> dataSourceMap = Map.of(
          writerKey, writerDataSource, readerKey, readerDataSource);

      routingDataSource.setTargetDataSources(dataSourceMap);
      routingDataSource.setDefaultTargetDataSource(writerDataSource);
      routingDataSource.afterPropertiesSet();

      return routingDataSource;
    }

    /**
     * 다중 데이터 소스를 설정
     *
     * @param routingDataSource 다중 데이터 소스
     * @return DataSource
     */
    @Primary
    @Bean(DATASOURCE_PREFIX + DATASOURCE_BEAN_NAME)
    public DataSource dataSourceReplication(
        @Qualifier(DATASOURCE_PREFIX + "RoutingDatasource") DataSource routingDataSource) {
      return new LazyConnectionDataSourceProxy(routingDataSource);
    }
  }

  /**
   * MyBatis SqlSessionFactory 설정
   *
   * @param dataSource 데이터 소스
   * @return 설정된 SqlSessionFactory 객체
   * @throws Exception exception
   */
  @Bean(DATASOURCE_PREFIX + "SessionFactory")
  public SqlSessionFactory sessionFactory(
      @Qualifier(DATASOURCE_PREFIX + DATASOURCE_BEAN_NAME) DataSource dataSource) throws Exception {

    SqlSessionFactoryBean factoryBean = new SqlSessionFactoryBean();
    factoryBean.setDataSource(dataSource);

    factoryBean.setTypeAliases(getTypeAliases(Constants.BASE_PACKAGE));
    factoryBean.setMapperLocations(
        new PathMatchingResourcePatternResolver().getResources("classpath:mapper/**/*.xml"));
    return factoryBean.getObject();
  }

  /**
   * 주어진 패키지에서 {@link Alias} 어노테이션이 선언된 클래스 타입을 검색하여 반환
   *
   * @param basePackage 검색할 기본 패키지 경로 (예: "com.example.package")
   * @return {@link Alias} 어노테이션이 붙은 클래스 타입 배열
   * @throws ClassNotFoundException 스캔된 클래스의 클래스 정의를 찾을 수 없을 때 발생
   */
  private Class<?>[] getTypeAliases(String basePackage) throws ClassNotFoundException {
    ClassPathScanningCandidateComponentProvider provider =
        new ClassPathScanningCandidateComponentProvider(false);
    provider.addIncludeFilter(new AnnotationTypeFilter(Alias.class));

    Set<Class<?>> typeAliases = new HashSet<>();
    for (BeanDefinition beanDefinition : provider.findCandidateComponents(basePackage)) {
      Class<?> clazz = Class.forName(beanDefinition.getBeanClassName());
      typeAliases.add(clazz);
    }
    return typeAliases.toArray(new Class[0]);
  }

  /**
   * MyBatis SqlSessionTemplate 설정
   *
   * @param sqlSessionFactory qlSessionFactory 객체
   * @return 설정된 SqlSessionTemplate 객체
   */
  @Bean(DATASOURCE_PREFIX + "SqlSessionTemplate")
  public SqlSessionTemplate sqlSessionTemplate(
      @Qualifier(DATASOURCE_PREFIX + "SessionFactory") SqlSessionFactory sqlSessionFactory) {
    return new SqlSessionTemplate(sqlSessionFactory);
  }

  /**
   * JPA 속성을 설정
   *
   * @return JpaProperties
   */
  @Primary
  @Bean(DATASOURCE_PREFIX + "JpaProperties")
  @ConfigurationProperties(prefix = DATASOURCE_PROPERTY_PREFIX + "jpa")
  public JpaProperties jpaProperties() {
    return new JpaProperties();
  }

  /**
   * 엔티티 매니저 팩토리를 설정
   *
   * @param dataSource    데이터 소스
   * @param jpaProperties JPA 속성
   * @return LocalContainerEntityManagerFactoryBean
   */
  @Primary
  @Bean(DATASOURCE_PREFIX + "EntityManagerFactory")
  public LocalContainerEntityManagerFactoryBean entityManagerFactory(
      @Qualifier(DATASOURCE_PREFIX + DATASOURCE_BEAN_NAME) DataSource dataSource,
      @Qualifier(DATASOURCE_PREFIX + "JpaProperties") JpaProperties jpaProperties) {
    return this.entityManagerFactoryBuilder(jpaProperties)
        .dataSource(dataSource)
        .packages(JPA_ENTITY_PACKAGES)
        .properties(jpaProperties.getProperties())
        .persistenceUnit(DATASOURCE_PREFIX + "EntityManager")
        .build();
  }

  /**
   * 엔티티 매니저 팩토리 빌더를 설정
   *
   * @param jpaProperties JPA 속성
   * @return EntityManagerFactoryBuilder
   */
  private EntityManagerFactoryBuilder entityManagerFactoryBuilder(JpaProperties jpaProperties) {
    HibernateJpaVendorAdapter jpaVendorAdapter = new HibernateJpaVendorAdapter();
    jpaVendorAdapter.setGenerateDdl(jpaProperties.isGenerateDdl());
    jpaVendorAdapter.setShowSql(jpaProperties.isShowSql());
    jpaVendorAdapter.setDatabasePlatform(jpaProperties.getDatabasePlatform());
    return new EntityManagerFactoryBuilder(jpaVendorAdapter, jpaProperties.getProperties(), null);
  }

  /**
   * 트랜잭션 매니저를 설정
   *
   * @param entityManagerFactory 엔티티 매니저 팩토리
   * @return PlatformTransactionManager
   */
  @Primary
  @Bean(DATASOURCE_PREFIX + "TransactionManager")
  public PlatformTransactionManager platformTransactionManager(
      @Qualifier(DATASOURCE_PREFIX + "EntityManagerFactory")
      LocalContainerEntityManagerFactoryBean entityManagerFactory
  ) {
    JpaTransactionManager jpaTransactionManager = new JpaTransactionManager();
    jpaTransactionManager.setEntityManagerFactory(entityManagerFactory.getObject());
    return jpaTransactionManager;
  }

  /**
   * JdbcTemplate 빈을 설정
   *
   * @param dataSource 데이터 소스
   * @return JdbcTemplate
   */
  @Bean(name = DATASOURCE_PREFIX + "JdbcTemplate")
  public JdbcTemplate jdbcTemplate(
      @Qualifier(DATASOURCE_PREFIX + DATASOURCE_BEAN_NAME) DataSource dataSource) {
    return new JdbcTemplate(dataSource);
  }

  /**
   * JPA 및 QueryDSL 설정을 위한 내부 클래스
   */
  @Configuration
  class QuerydslConfig {

    @PersistenceContext(unitName = DATASOURCE_PREFIX + "EntityManager")
    private EntityManager mainEntityManager;

    /**
     * JPAQueryFactory 빈을 설정
     *
     * @return JPAQueryFactory
     */
    @Bean
    public JPAQueryFactory mainJpaQueryFactory() {
      return new JPAQueryFactory(mainEntityManager);
    }
  }
}
