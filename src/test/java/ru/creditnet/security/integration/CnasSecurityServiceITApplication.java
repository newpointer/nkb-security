package ru.creditnet.security.integration;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;
import ru.creditnet.security.conf.CnasWebSecurityConfig;

/**
 * @author val
 */
@Import(CnasWebSecurityConfig.class)
@EnableAutoConfiguration
public class CnasSecurityServiceITApplication {

    public static void main(String[] args) {
        SpringApplication.run(CnasSecurityServiceITApplication.class, args);
    }
}
