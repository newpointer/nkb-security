package ru.creditnet.security;

import org.springframework.util.Assert;

import java.io.Serializable;
import java.security.Principal;
import java.util.Set;

/**
 * @author Alexander Yastrebov
 */
public class TicketPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 20140330;
    //
    private final String userId;
    private final String ticketId;
    private final Object ticket;
    private final Set<String> permissions;

    public TicketPrincipal(String userId, String ticketId, Object ticket, Set<String> permissions) {
        Assert.hasText(userId);
        Assert.hasText(ticketId);
        Assert.notNull(ticket);
        Assert.notNull(permissions);

        this.userId = userId;
        this.ticketId = ticketId;
        this.ticket = ticket;
        this.permissions = permissions;
    }

    @Override
    public String getName() {
        // Используем ИД тикета в качестве имени принципала
        return ticketId;
    }

    public String getUserId() {
        return userId;
    }

    public String getTicketId() {
        return ticketId;
    }

    public Object getTicket() {
        return ticket;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    @Override
    public String toString() {
        return "TicketPrincipal{"
                + "userId=" + userId
                + ", ticketId=" + ticketId
                + ", ticket=" + ticket
                + '}';
    }
}
