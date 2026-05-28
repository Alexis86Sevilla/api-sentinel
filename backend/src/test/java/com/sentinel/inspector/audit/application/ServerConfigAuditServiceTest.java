package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ServerConfigAuditServiceTest {

    private ServerConfigAuditService serverConfigAuditService;

    @BeforeEach
    void setUp() {
        serverConfigAuditService = new ServerConfigAuditService();
    }

    @Test
    void shouldCreateServiceInstance() {
        assertNotNull(serverConfigAuditService);
    }

    @Test
    void shouldReturnValidResultForSecureSite() {
        SecurityAuditResult result = serverConfigAuditService.auditServerConfig("https://www.google.com");
        
        assertNotNull(result);
        assertTrue(result.score() >= 0 && result.score() <= 100);
        assertEquals(4, result.items().size());
        
        // Check all items are present
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("https")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("redirect")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("compression")));
        assertTrue(result.items().stream().anyMatch(i -> i.key().equals("directory-listing")));
    }

    @Test
    void shouldHandleHttpUrl() {
        // Testing with HTTP to check redirect detection
        SecurityAuditResult result = serverConfigAuditService.auditServerConfig("http://www.google.com");
        
        assertNotNull(result);
        assertTrue(result.score() >= 0);
        assertEquals(4, result.items().size());
    }

    @Test
    void shouldHandleInvalidUrl() {
        SecurityAuditResult result = serverConfigAuditService.auditServerConfig("not-a-valid-url");
        
        assertNotNull(result);
        assertTrue(result.score() >= 0 && result.score() <= 100); // Any valid score
        assertEquals(4, result.items().size());
    }
}