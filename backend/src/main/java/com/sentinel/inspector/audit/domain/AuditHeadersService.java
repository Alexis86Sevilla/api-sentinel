package com.sentinel.inspector.audit.domain;

import com.sentinel.inspector.audit.domain.ports.HeaderScanner;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

public class AuditHeadersService {

    private static final long HSTS_MIN_MAX_AGE = 31536000L; // 1 year
    private static final int SCORE_MISSING_HSTS = 20;
    private static final int SCORE_HSTS_SHORT_MAX_AGE = 15;
    private static final int SCORE_HSTS_INVALID_MAX_AGE = 5;
    private static final int SCORE_HSTS_MISSING_MAX_AGE_DIRECTIVE = 10;
    private static final int SCORE_MISSING_CSP = 30;
    private static final int SCORE_CSP_UNSAFE_DIRECTIVE = 25;
    private static final int SCORE_MISSING_XFO = 10;
    private static final int SCORE_XFO_INVALID_VALUE = 5;
    private static final int SCORE_MISSING_XCTO = 10;
    private static final int SCORE_XCTO_INVALID_VALUE = 5;

    private final HeaderScanner headerScanner;

    public AuditHeadersService(HeaderScanner headerScanner) {
        this.headerScanner = headerScanner;
    }

    public AuditReport performAudit(String url) {
        AuditReport rawReport = headerScanner.scanHeaders(URI.create(url));

        List<String> issues = new ArrayList<>();
        int score = 100;

        score -= checkHSTSHeader(rawReport.headers(), issues);
        score -= checkCSPHeader(rawReport.headers(), issues);
        score -= checkXFOHeader(rawReport.headers(), issues);
        score -= checkXCTOHeader(rawReport.headers(), issues);

        return new AuditReport(
            rawReport.targetUrl(),
            LocalDateTime.now(),
            rawReport.headers(),
            issues,
            Math.max(0, score)
        );
    }

    private int checkHSTSHeader(Map<String, String> headers, List<String> issues) {
        int deduction = 0;
        String hstsHeader = headers.get("strict-transport-security");
        if (hstsHeader == null) {
            issues.add("Missing Strict-Transport-Security header.");
            deduction += SCORE_MISSING_HSTS;
        } else {
            if (hstsHeader.contains("max-age=")) {
                String maxAgeString = hstsHeader.substring(hstsHeader.indexOf("max-age=") + 8);
                if (maxAgeString.contains(";")) {
                    maxAgeString = maxAgeString.substring(0, maxAgeString.indexOf(";"));
                }
                try {
                    long maxAge = Long.parseLong(maxAgeString);
                    if (maxAge < HSTS_MIN_MAX_AGE) {
                        issues.add("HSTS header has too short max-age.");
                        deduction += SCORE_HSTS_SHORT_MAX_AGE;
                    }
                } catch (NumberFormatException e) {
                    issues.add("HSTS header has invalid max-age value.");
                    deduction += SCORE_HSTS_INVALID_MAX_AGE;
                }
            } else {
                issues.add("HSTS header is missing max-age directive.");
                deduction += SCORE_HSTS_MISSING_MAX_AGE_DIRECTIVE;
            }
        }
        return deduction;
    }

    private int checkCSPHeader(Map<String, String> headers, List<String> issues) {
        int deduction = 0;
        String cspHeader = headers.get("content-security-policy");
        if (cspHeader == null) {
            issues.add("Missing Content-Security-Policy header.");
            deduction += SCORE_MISSING_CSP;
        } else {
            if (cspHeader.contains("'unsafe-inline'") || cspHeader.contains("'unsafe-eval'")) {
                issues.add("Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval'.");
                deduction += SCORE_CSP_UNSAFE_DIRECTIVE;
            }
        }
        return deduction;
    }

    private int checkXFOHeader(Map<String, String> headers, List<String> issues) {
        int deduction = 0;
        String xfoHeader = headers.get("x-frame-options");
        if (xfoHeader == null) {
            issues.add("Missing X-Frame-Options header.");
            deduction += SCORE_MISSING_XFO;
        } else {
            if (!"DENY".equalsIgnoreCase(xfoHeader) && !"SAMEORIGIN".equalsIgnoreCase(xfoHeader)) {
                issues.add("X-Frame-Options header has invalid value.");
                deduction += SCORE_XFO_INVALID_VALUE;
            }
        }
        return deduction;
    }

    private int checkXCTOHeader(Map<String, String> headers, List<String> issues) {
        int deduction = 0;
        String xctoHeader = headers.get("x-content-type-options");
        if (xctoHeader == null) {
            issues.add("Missing X-Content-Type-Options header.");
            deduction += SCORE_MISSING_XCTO;
        } else {
            if (!"nosniff".equalsIgnoreCase(xctoHeader)) {
                issues.add("X-Content-Type-Options header has invalid value.");
                deduction += SCORE_XCTO_INVALID_VALUE;
            }
        }
        return deduction;
    }
}
