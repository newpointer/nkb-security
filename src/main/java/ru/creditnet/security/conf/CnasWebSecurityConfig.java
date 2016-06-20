package ru.creditnet.security.conf;

import creditnet.cnas.auth.SecurityServiceEndpoint;
import creditnet.cnas.service.ClientRequestServiceEndpoint;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.util.Assert;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.impl.AnonymousSecurityServiceWrapper;
import ru.creditnet.security.impl.CnasSecurityService;

/**
 * @author val
 */
@Configuration
@Import(WebSecurityConfig.class)
public class CnasWebSecurityConfig {

    private final <T> T endpoint(Class<T> serviceClass, String address) {
        final JaxWsProxyFactoryBean jaxWsProxyFactoryBean = new JaxWsProxyFactoryBean();
        jaxWsProxyFactoryBean.setServiceClass(serviceClass);
        jaxWsProxyFactoryBean.setAddress(address);
        @SuppressWarnings("unchecked")
        T t = (T) jaxWsProxyFactoryBean.create();
        return t;
    }

    @Bean
    public SecurityServiceEndpoint cnasSecurityServiceEndpoint(ConfigProperties properties) {
        Assert.notNull(properties.getCnasSecurityServiceUrl(), "'cnasSecurityServiceUrl' must not be null");

        return endpoint(SecurityServiceEndpoint.class, properties.getCnasSecurityServiceUrl());
    }

    @Bean
    public ClientRequestServiceEndpoint cnasClientRequestServiceEndpoint(ConfigProperties properties) {
        Assert.notNull(properties.getCnasClientRequestServiceUrl(), "'cnasClientRequestServiceUrl' must not be null");

        return endpoint(ClientRequestServiceEndpoint.class, properties.getCnasClientRequestServiceUrl());
    }

    @Bean
    public SecurityService securityService(SecurityServiceEndpoint securityServiceEndpoint,
                                           ClientRequestServiceEndpoint clientRequestServiceEndpoint,
                                           ConfigProperties properties) {
        SecurityService securityService = new CnasSecurityService(
                securityServiceEndpoint,
                clientRequestServiceEndpoint,
                properties.getTicketExpiryPeriodSeconds());
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
