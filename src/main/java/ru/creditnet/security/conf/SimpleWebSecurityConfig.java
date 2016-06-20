package ru.creditnet.security.conf;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.impl.AnonymousSecurityServiceWrapper;
import ru.creditnet.security.impl.SimpleSecurityService;

/**
 * @author val
 */
@Configuration
@Import(WebSecurityConfig.class)
public class SimpleWebSecurityConfig {

    @Bean
    public SecurityService securityService(UserDetailsService userDetailsService, ConfigProperties properties) {
        SecurityService securityService = new SimpleSecurityService(userDetailsService);
        securityService = wrapSecurityService(securityService, properties);
        return securityService;
    }

    protected SecurityService wrapSecurityService(SecurityService securityService, ConfigProperties properties) {
        if (!properties.getAnonymousPermissions().isEmpty()) {
            AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
            securityService = new AnonymousSecurityServiceWrapper(authenticationTrustResolver, securityService);
        }
        return securityService;
    }
}
