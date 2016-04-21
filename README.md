# nkb-security

## Описание

Интеграция с внутренней системой безопасности.
Предоставляет:
* SecurityService - API
* сконфигурированный FilterChainProxy

## Сборка

    $ mvn

### Интеграционные тесты

    $ echo "logging.level.ru.creditnet.security=debug
    ru.creditnet.security.cnasSecurityServiceUrl=http://testing0.nkb:8080/cnas/services/SecurityService?wsdl
    ru.creditnet.security.cnasClientRequestServiceUrl=http://testing0.nkb:8080/cnas/services/ClientRequestService?wsdl
    test.cnasUsername=secretusername
    test.cnasPassword=secretpassword" > ./my.properties
    $ mvn -Dspring.config.location=./my.properties -PintegrationOnly

## Использование

    @RestController
    public class Controller {

        @Autowired
        SecurityService securityService;

        @RequestMapping
        public ResponseEntity<String> securityResource() {
            securityService.ensureHasPermission("SEARCH_RELATED");
            return ResponseEntity.ok("security information");
        }
    }

## Настройки

### Общие

    <dependency>
        <groupId>ru.creditnet.security</groupId>
        <artifactId>nkb-security</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>

    echo "logging.level.ru.creditnet.security=debug
    ru.creditnet.security.anonymousPermissions[0]=SEARCH
    ru.creditnet.security.anonymousPermissions[1]=SEARCH_RELATED
    #ru.creditnet.security.cnasTicketCookieName=creditnet_ticket
    #ru.creditnet.security.securityFilterUrlPattern=/**
    " > application.properties

Если не заданы **ru.creditnet.security.anonymousPermissions** - то анонимный доступ запрещен.

### SimpleWebSecurityConfig - pretty good for testing

    @Import(SimpleWebSecurityConfig.class)
    @SpringBootApplication
    public class MyApplication {

        public static void main(String[] args) {
            SpringApplication.run(MyApplication.class, args);
        }

        @Bean
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager(Arrays.asList(
                new User("user0", "user0", Arrays.asList(new SimpleGrantedAuthority("SEARCH_TRACES"))),
                new User("user1", "user1", Arrays.asList(new SimpleGrantedAuthority("SEARCH", "SEARCH_RELATED")))
            ));
        }
    }

### CnasWebSecurityConfig

    @Import(CnasWebSecurityConfig.class)
    @SpringBootApplication
    public class MyApplication {

        public static void main(String[] args) {
            SpringApplication.run(MyApplication.class, args);
        }
    }

    echo "
    ru.creditnet.security.cnasSecurityServiceUrl=http://testing0.nkb:8080/cnas/services/SecurityService?wsdl
    ru.creditnet.security.cnasClientRequestServiceUrl=http://testing0.nkb:8080/cnas/services/ClientRequestService?wsdl
    #ru.creditnet.security.cnasTicketExpiryPeriodSeconds=3600
    " > application.properties
