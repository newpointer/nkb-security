package ru.creditnet.security.impl;

import creditnet.cnas.auth.SecurityServiceEndpoint;
import creditnet.cnas.auth.SsoTicket;
import creditnet.cnas.auth.exception.AuthException;
import creditnet.cnas.common.NcbUUID;
import creditnet.cnas.service.ClientRequestServiceEndpoint;
import creditnet.cnas.service.PurchaseListPossibility;
import creditnet.cnas.service.PurchasePossibility;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.Assert;
import ru.creditnet.security.Permissions;
import ru.creditnet.security.Product;
import ru.creditnet.security.TicketPrincipal;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toSet;

/**
 * @author Alexander Yastrebov
 * @author ankostyuk
 * @author val
 */
public class CnasSecurityService extends AbstractSecurityService {

    private static final String[][] PERMISSION_PRODUCTS = new String[][]{
            {Permissions.SEARCH.name(), Product.RELATIONS_SEARCH.getProductCode()}, //
            {Permissions.SEARCH_RELATED.name(), Product.RELATIONS_FIND_RELATED.getProductCode()}, //
            {Permissions.SEARCH_TRACES.name(), Product.RELATIONS_FIND_RELATIONS.getProductCode()}, //
            //
            {Permissions.REQUEST_EGRUL_COMPANY.name(), Product.EGRUL_COMPANY.getProductCode()}, //
            {Permissions.REQUEST_EGRUL_INDIVIDUAL_FOUNDER.name(), Product.EGRUL_INDIVIDUAL_FOUNDER.getProductCode()}, //
            {Permissions.REQUEST_EGRUL_INDIVIDUAL_EXECUTIVE.name(), Product.EGRUL_INDIVIDUAL_EXECUTIVE.getProductCode()}, //
    };
    private static final List<String> PRODUCTS = Stream.of(PERMISSION_PRODUCTS).map(a -> a[1]).collect(toList());

    private final SecurityServiceEndpoint securityServiceEndpoint;
    private final ClientRequestServiceEndpoint clientRequestServiceEndpoint;
    private int ticketExpiryPeriodSeconds = 3600;

    public CnasSecurityService(SecurityServiceEndpoint securityServiceEndpoint,
                               ClientRequestServiceEndpoint clientRequestServiceEndpoint,
                               Integer ticketExpiryPeriodSeconds) {
        Assert.notNull(securityServiceEndpoint, "'securityServiceEndpoint' must not be null");
        this.securityServiceEndpoint = securityServiceEndpoint;

        Assert.notNull(clientRequestServiceEndpoint, "'clientRequestServiceEndpoint' must not be null");
        this.clientRequestServiceEndpoint = clientRequestServiceEndpoint;

        Assert.notNull(ticketExpiryPeriodSeconds, "'ticketExpiryPeriodSeconds' must not be null ");
        Assert.isTrue(ticketExpiryPeriodSeconds > 0, "'ticketExpiryPeriodSeconds' must be greater than 0");
        this.ticketExpiryPeriodSeconds = ticketExpiryPeriodSeconds;
    }

    @Override
    public TicketPrincipal authenticate(String login, String password, String ip) {
        Assert.hasText(login);
        Assert.hasText(password);

        SsoTicket ssoTicket;
        try {
            ssoTicket = securityServiceEndpoint.authenticate(login, password, ip, ticketExpiryPeriodSeconds);
        } catch (Exception ex) {
            throw new BadCredentialsException("Authentication failed", ex);
        }

        String userId = ssoTicket.getUserUUID().getId();
        String ticketId = ssoTicket.getId().getId();

        return new TicketPrincipal(userId, ticketId, ssoTicket, getPermissions(ssoTicket));
    }

    @Override
    public TicketPrincipal authenticateWithTicket(String ticket) {
        Assert.notNull(ticket);
        NcbUUID uuid = parseUUID(ticket);
        if (uuid == null) {
            throw new BadCredentialsException("Invalid ticket");
        }

        SsoTicket ssoTicket;
        try {
            ssoTicket = securityServiceEndpoint.authenticateWithTicket(uuid);
        } catch (Exception ex) {
            throw new AuthenticationServiceException("Authentication failed", ex);
        }

        String userId = ssoTicket.getUserUUID().getId();
        String ticketId = ssoTicket.getId().getId();

        return new TicketPrincipal(userId, ticketId, ssoTicket, getPermissions(ssoTicket));
    }

    private NcbUUID parseUUID(String s) {
        try {
            return new NcbUUID(s);
        } catch (NumberFormatException ex) {
            logger.warn("Illegal UUID: {}", s);
            return null;
        }
    }

    private Set<String> getPermissions(SsoTicket ssoTicket) {
        PurchaseListPossibility purchasePossibilities;
        try {
            purchasePossibilities = clientRequestServiceEndpoint.getPurchasePossibilities(ssoTicket, PRODUCTS);
        } catch (AuthException ex) {
            throw new AuthenticationServiceException("Product purchase info request failed", ex);
        }

        logger.debug("possibilities: {}", purchasePossibilities.getProductPossibilities());

        List<PurchasePossibility> possibilities = purchasePossibilities.getProductPossibilities();
        Assert.isTrue(PERMISSION_PRODUCTS.length == possibilities.size());

        Set<String> result = Stream.of(Permissions.stringValues()).collect(toSet());

        for (int i = 0; i < PERMISSION_PRODUCTS.length; i++) {
            if (!possibilities.get(i).isPossible()) {
                result.remove(PERMISSION_PRODUCTS[i][0]);
            }
        }
        return Collections.unmodifiableSet(result);
    }
}
