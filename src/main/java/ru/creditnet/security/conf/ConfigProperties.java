package ru.creditnet.security.conf;

import org.springframework.boot.context.properties.ConfigurationProperties;
import ru.creditnet.security.Permissions;

import java.util.ArrayList;
import java.util.List;

/**
 * @author val
 */
@ConfigurationProperties(prefix = "ru.creditnet.security")
public class ConfigProperties {

    private String cnasSecurityServiceUrl;
    private String cnasClientRequestServiceUrl;
    private int ticketExpiryPeriodSeconds = 3600;
    private String cnasTicketCookieName = "creditnet_ticket";
    private String securityFilterUrlPattern = "/**";
    private List<Permissions> anonymousPermissions = new ArrayList<>();

    public String getCnasSecurityServiceUrl() {
        return cnasSecurityServiceUrl;
    }

    public void setCnasSecurityServiceUrl(String cnasSecurityServiceUrl) {
        this.cnasSecurityServiceUrl = cnasSecurityServiceUrl;
    }

    public String getCnasClientRequestServiceUrl() {
        return cnasClientRequestServiceUrl;
    }

    public void setCnasClientRequestServiceUrl(String cnasClientRequestServiceUrl) {
        this.cnasClientRequestServiceUrl = cnasClientRequestServiceUrl;
    }

    public int getTicketExpiryPeriodSeconds() {
        return ticketExpiryPeriodSeconds;
    }

    public void setTicketExpiryPeriodSeconds(int ticketExpiryPeriodSeconds) {
        this.ticketExpiryPeriodSeconds = ticketExpiryPeriodSeconds;
    }

    public String getCnasTicketCookieName() {
        return cnasTicketCookieName;
    }

    public void setCnasTicketCookieName(String cnasTicketCookieName) {
        this.cnasTicketCookieName = cnasTicketCookieName;
    }

    public String getSecurityFilterUrlPattern() {
        return securityFilterUrlPattern;
    }

    public void setSecurityFilterUrlPattern(String securityFilterUrlPattern) {
        this.securityFilterUrlPattern = securityFilterUrlPattern;
    }

    public List<Permissions> getAnonymousPermissions() {
        return anonymousPermissions;
    }

    public void setAnonymousPermissions(List<Permissions> anonymousPermissions) {
        this.anonymousPermissions = anonymousPermissions;
    }
}
