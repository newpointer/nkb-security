package ru.creditnet.security.conf;

import creditnet.cnas.auth.SecurityServiceEndpoint;
import creditnet.cnas.service.ClientRequestServiceEndpoint;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.util.Assert;
import ru.creditnet.security.SecurityService;
import ru.creditnet.security.impl.CnasSecurityService;

/**
 * @author val
 */
@Configuration
@EnableConfigurationProperties(ConfigProperties.class)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class CnasWebSecurityConfig extends WebSecurityConfig {

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
    public SecurityService cnasSecurityService(
            SecurityServiceEndpoint securityServiceEndpoint,
            ClientRequestServiceEndpoint clientRequestServiceEndpoint,
            ConfigProperties configProperties) throws Exception {
        SecurityService securityService = new CnasSecurityService(
                securityServiceEndpoint,
                clientRequestServiceEndpoint,
                configProperties.getTicketExpiryPeriodSeconds());
        securityService = wrapSecurityService(securityService, configProperties);
        return securityService;
    }
}
