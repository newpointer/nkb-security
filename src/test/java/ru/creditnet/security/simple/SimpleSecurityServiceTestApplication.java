package ru.creditnet.security.simple;

import org.springframework.boot.SpringApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;
import ru.creditnet.security.TestUtils;
import ru.creditnet.security.conf.SimpleWebSecurityConfig;

/**
 * @author val
 */
@Import(SimpleWebSecurityConfig.class)
public class SimpleSecurityServiceTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(SimpleSecurityServiceTestApplication.class, args);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return TestUtils.userDetailsService;
    }
}
