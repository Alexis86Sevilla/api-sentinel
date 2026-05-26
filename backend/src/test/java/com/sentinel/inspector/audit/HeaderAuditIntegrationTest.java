package com.sentinel.inspector.audit;

import com.sentinel.inspector.audit.adapter.HttpHeaderScannerAdapter;
import com.sentinel.inspector.audit.domain.AuditHeadersService;
import com.sentinel.inspector.audit.domain.AuditReport;
import com.sentinel.inspector.audit.domain.ports.HeaderScanner;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@SpringBootTest
class HeaderAuditIntegrationTest {

    private MockWebServer mockWebServer;
    private HttpHeaderScannerAdapter httpHeaderScannerAdapter;
    private AuditHeadersService auditHeadersService;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        httpHeaderScannerAdapter = new HttpHeaderScannerAdapter(); // Use real adapter
        auditHeadersService = new AuditHeadersService(httpHeaderScannerAdapter); // Inject real adapter
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    @DisplayName("Should pass audit for headers with valid security configurations")
    void shouldPassAuditWithValidSecurityHeaders() {
        // Arrange
        String mockUrl = mockWebServer.url("/").toString();
        URI targetUri = URI.create(mockUrl);

        mockWebServer.enqueue(new MockResponse()
                .addHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                .addHeader("Content-Security-Policy", "default-src 'self'")
                .addHeader("X-Frame-Options", "DENY")
                .addHeader("X-Content-Type-Options", "nosniff")
                .setResponseCode(200));

        // Act
        AuditReport report = auditHeadersService.performAudit(mockUrl);

        // Assert
        assertNotNull(report);
        assertTrue(report.issues().isEmpty(), "No issues should be reported for valid headers.");
        assertEquals(100, report.score(), "Score should be 100 for valid headers.");
    }

    @Test
    @DisplayName("Should report issues for missing security headers")
    void shouldReportIssuesForMissingSecurityHeaders() {
        // Arrange
        String mockUrl = mockWebServer.url("/").toString();
        URI targetUri = URI.create(mockUrl);

        mockWebServer.enqueue(new MockResponse()
                .setResponseCode(200)); // No security headers

        // Act
        AuditReport report = auditHeadersService.performAudit(mockUrl);

        // Assert
        assertNotNull(report);
        assertFalse(report.issues().isEmpty(), "Issues should be reported for missing headers.");
        assertTrue(report.issues().contains("Missing Strict-Transport-Security header."), "Should report missing HSTS.");
        assertTrue(report.issues().contains("Missing Content-Security-Policy header."), "Should report missing CSP.");
        assertTrue(report.issues().contains("Missing X-Frame-Options header."), "Should report missing X-Frame-Options.");
        assertTrue(report.issues().contains("Missing X-Content-Type-Options header."), "Should report missing X-Content-Type-Options.");
        assertTrue(report.score() < 100, "Score should be reduced for missing headers.");
    }

    @Test
    @DisplayName("Should report issues for invalid security header values")
    void shouldReportIssuesForInvalidSecurityHeaderValues() {
        // Arrange
        String mockUrl = mockWebServer.url("/").toString();
        URI targetUri = URI.create(mockUrl);

        mockWebServer.enqueue(new MockResponse()
                .addHeader("Strict-Transport-Security", "max-age=1000") // Too short
                .addHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline'") // Unsafe CSP
                .addHeader("X-Frame-Options", "ALLOW-FROM http://bad.com") // Invalid for modern browsers
                .addHeader("X-Content-Type-Options", "sniff") // Invalid
                .setResponseCode(200));

        // Act
        AuditReport report = auditHeadersService.performAudit(mockUrl);

        // Assert
        assertNotNull(report);
        assertFalse(report.issues().isEmpty(), "Issues should be reported for invalid header values.");
        assertTrue(report.issues().contains("HSTS header has too short max-age."), "Should report invalid HSTS max-age.");
        assertTrue(report.issues().contains("Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval'."), "Should report unsafe CSP.");
        assertTrue(report.issues().contains("X-Frame-Options header has invalid value."), "Should report invalid X-Frame-Options.");
        assertTrue(report.issues().contains("X-Content-Type-Options header has invalid value."), "Should report invalid X-Content-Type-Options.");
        assertTrue(report.score() < 100, "Score should be reduced for invalid header values.");
    }
}
