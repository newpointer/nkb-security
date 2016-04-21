package ru.creditnet.security.web;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetailsService;
import ru.creditnet.security.TestUtils;
import ru.creditnet.security.conf.SimpleWebSecurityConfig;

/**
 * @author val
 */
@Import(SimpleWebSecurityConfig.class)
@SpringBootApplication
public class WebApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebApplication.class, args);
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return TestUtils.userDetailsService;
    }
}
