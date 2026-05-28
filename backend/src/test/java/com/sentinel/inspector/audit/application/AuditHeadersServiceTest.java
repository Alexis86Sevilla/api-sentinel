package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.port.HeaderScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class AuditHeadersServiceTest {

    private HeaderScanner headerScanner;
    private AuditHeadersService auditHeadersService;

    @BeforeEach
    void setUp() {
        headerScanner = Mockito.mock(HeaderScanner.class);
        auditHeadersService = new AuditHeadersService(headerScanner);
    }

    @Test
    void shouldCreateServiceInstance() {
        assertNotNull(auditHeadersService);
    }

    @Test
    void shouldReportMissingSecurityHeaders() {
        String testUrl = "http://example.com";
        URI testUri = URI.create(testUrl);

        Map<String, String> headers = new HashMap<>();
        headers.put("strict-transport-security", "max-age=10000");
        headers.put("content-security-policy", "default-src 'self' 'unsafe-inline'");
        headers.put("x-frame-options", "ALLOWALL");
        headers.put("x-content-type-options", "sniff");

        Mockito.when(headerScanner.scanHeaders(testUri)).thenReturn(headers);

        SecurityAuditResult auditReport = auditHeadersService.performAudit(testUrl);

        assertNotNull(auditReport);
        assertFalse(auditReport.items().isEmpty(), "Items list should not be empty");
        assertTrue(auditReport.score() < 100, "Score should be reduced due to issues");

        assertTrue(auditReport.items().stream().anyMatch(i -> 
            i.key().equals("strict-transport-security") && i.status().equals("warning")));
        assertTrue(auditReport.items().stream().anyMatch(i -> 
            i.key().equals("x-frame-options") && i.status().equals("error")));
        assertTrue(auditReport.items().stream().anyMatch(i -> 
            i.key().equals("content-security-policy") && i.status().equals("warning")));
        assertTrue(auditReport.items().stream().anyMatch(i -> 
            i.key().equals("x-content-type-options") && i.status().equals("error")));
    }
}