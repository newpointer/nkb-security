package ru.creditnet.security.conf;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.impl.SimpleSecurityService;

/**
 * @author val
 */
@Configuration
@EnableConfigurationProperties(ConfigProperties.class)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SimpleWebSecurityConfig extends WebSecurityConfig {

    @Bean
    public SecurityService simpleSecurityService(
            ConfigProperties configProperties,
            UserDetailsService userDetailsService) throws Exception {
        SecurityService securityService = new SimpleSecurityService(userDetailsService);
        securityService = wrapSecurityService(securityService, configProperties);
        return securityService;
    }
}
