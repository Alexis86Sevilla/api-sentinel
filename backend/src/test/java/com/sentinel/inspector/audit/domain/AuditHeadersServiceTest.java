package com.sentinel.inspector.audit.domain;

import com.sentinel.inspector.audit.domain.ports.HeaderScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        // RED: Test should fail because AuditHeadersService doesn't correctly identify missing headers yet

        String testUrl = "http://example.com";
        URI testUri = URI.create(testUrl);

        // Mock a raw report with missing HSTS and CSP
        Map<String, String> headers = new HashMap<>();
        // Mock a raw report with missing HSTS (bad max-age) and CSP, and missing X-Frame-Options
        headers.put("strict-transport-security", "max-age=10000"); // Invalid max-age
        headers.put("content-security-policy", "default-src 'self' 'unsafe-inline'"); // CSP with unsafe-inline
        headers.put("x-frame-options", "ALLOWALL"); // Invalid X-Frame-Options
        headers.put("x-content-type-options", "sniff"); // Invalid X-Content-Type-Options

        AuditReport rawReport = new AuditReport(
                testUrl,
                LocalDateTime.now(),
                headers,
                Collections.emptyList(),
                100 // Starting score
        );

        Mockito.when(headerScanner.scanHeaders(testUri)).thenReturn(rawReport);

        AuditReport auditReport = auditHeadersService.performAudit(testUrl);

        assertNotNull(auditReport);
        assertFalse(auditReport.issues().isEmpty(), "Issues list should not be empty");
        assertTrue(auditReport.issues().contains("HSTS header has too short max-age."), "Should report HSTS with short max-age");
        assertFalse(auditReport.issues().contains("Missing X-Frame-Options header."), "Should NOT report missing X-Frame-Options when present");
        assertTrue(auditReport.issues().contains("X-Frame-Options header has invalid value."), "Should report invalid X-Frame-Options");
        assertFalse(auditReport.issues().contains("Missing Content-Security-Policy header."), "Should NOT report missing CSP when present");
        assertTrue(auditReport.issues().contains("Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval'."), "Should report unsafe CSP");
        assertTrue(auditReport.issues().contains("X-Content-Type-Options header has invalid value."), "Should report invalid X-Content-Type-Options");
        assertTrue(auditReport.score() < 100, "Score should be reduced due to issues");
    }
}
