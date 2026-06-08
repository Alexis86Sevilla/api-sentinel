package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import com.sentinel.inspector.audit.domain.port.HeaderScanner;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class AuditHeadersService {
    private static final long HSTS_MIN_MAX_AGE = 31536000L;
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

    private static final int SCORE_MISSING_OR_UNSAFE_RP = 5;

    private final HeaderScanner headerScanner;

    public AuditHeadersService(HeaderScanner headerScanner) {
        this.headerScanner = headerScanner;
    }

    public SecurityAuditResult performAudit(String url) {
        Map<String, String> headers = headerScanner.scanHeaders(URI.create(url));

        List<SecurityItem> items = new ArrayList<>();
        int scoreDeductions = 0;

        // Check HSTS
        HstsResult hsts = checkHSTSHeader(headers);
        items.add(hsts.item);
        scoreDeductions += hsts.deduction;

        // Check CSP
        CspResult csp = checkCSPHeader(headers);
        items.add(csp.item);
        scoreDeductions += csp.deduction;

        // Check XFO
        XfoResult xfo = checkXFOHeader(headers);
        items.add(xfo.item);
        scoreDeductions += xfo.deduction;

        // Check XCTO
        XctoResult xcto = checkXCTOHeader(headers);
        items.add(xcto.item);
        scoreDeductions += xcto.deduction;

        // Check Referrer-Policy
        RpResult rp = checkReferrerPolicyHeader(headers);
        items.add(rp.item);
        scoreDeductions += rp.deduction;

        int score = Math.max(0, 100 - scoreDeductions);

        return new SecurityAuditResult(score, items);
    }

    private HstsResult checkHSTSHeader(Map<String, String> headers) {
        String hstsHeaderValue = headers.get("strict-transport-security");
        String status = "success";
        String value = "header.configured";
        int deduction = 0;

        if (hstsHeaderValue == null) {
            status = "error";
            value = "header.notConfigured";
            deduction = SCORE_MISSING_HSTS;
        } else {
            if (hstsHeaderValue.contains("max-age=")) {
                String maxAgeString = hstsHeaderValue.substring(hstsHeaderValue.indexOf("max-age=") + 8);
                if (maxAgeString.contains(";")) {
                    maxAgeString = maxAgeString.substring(0, maxAgeString.indexOf(";"));
                }
                try {
                    long maxAge = Long.parseLong(maxAgeString);
                    if (maxAge < HSTS_MIN_MAX_AGE) {
                        status = "warning";
                        value = "header.hsts.lowMaxAge";
                        deduction = SCORE_HSTS_SHORT_MAX_AGE;
                    }
                } catch (NumberFormatException e) {
                    status = "error";
                    value = "header.hsts.invalidMaxAge";
                    deduction = SCORE_HSTS_INVALID_MAX_AGE;
                }
            } else {
                status = "warning";
                value = "header.hsts.missingMaxAge";
                deduction = SCORE_HSTS_MISSING_MAX_AGE_DIRECTIVE;
            }
        }
        return new HstsResult(
            new SecurityItem("strict-transport-security", "Strict-Transport-Security", value, status),
            deduction
        );
    }

    private CspResult checkCSPHeader(Map<String, String> headers) {
        String cspHeaderValue = headers.get("content-security-policy");
        String status = "success";
        String value = "header.configured";
        int deduction = 0;

        if (cspHeaderValue == null) {
            status = "error";
            value = "header.notConfigured";
            deduction = SCORE_MISSING_CSP;
        } else {
            if (cspHeaderValue.contains("'unsafe-inline'") || cspHeaderValue.contains("'unsafe-eval'")) {
                status = "warning";
                value = "header.csp.unsafeDirectives";
                deduction = SCORE_CSP_UNSAFE_DIRECTIVE;
            }
        }
        return new CspResult(
            new SecurityItem("content-security-policy", "Content-Security-Policy", value, status),
            deduction
        );
    }

    private XfoResult checkXFOHeader(Map<String, String> headers) {
        String xfoHeaderValue = headers.get("x-frame-options");
        String status = "success";
        String value = "header.configured";
        int deduction = 0;

        if (xfoHeaderValue == null) {
            status = "error";
            value = "header.notConfigured";
            deduction = SCORE_MISSING_XFO;
        } else {
            if (!("DENY".equalsIgnoreCase(xfoHeaderValue) || "SAMEORIGIN".equalsIgnoreCase(xfoHeaderValue))) {
                status = "error";
                value = "header.xframe.invalidValue:" + xfoHeaderValue;
                deduction = SCORE_XFO_INVALID_VALUE;
            } else {
                value = xfoHeaderValue.toUpperCase();
            }
        }
        return new XfoResult(
            new SecurityItem("x-frame-options", "X-Frame-Options", value, status),
            deduction
        );
    }

    private XctoResult checkXCTOHeader(Map<String, String> headers) {
        String xctoHeaderValue = headers.get("x-content-type-options");
        String status = "success";
        String value = "header.configured";
        int deduction = 0;

        if (xctoHeaderValue == null) {
            status = "error";
            value = "header.notConfigured";
            deduction = SCORE_MISSING_XCTO;
        } else {
            if (!("nosniff".equalsIgnoreCase(xctoHeaderValue))) {
                status = "error";
                value = "header.xcto.invalidValue:" + xctoHeaderValue;
                deduction = SCORE_XCTO_INVALID_VALUE;
            } else {
                value = "nosniff";
            }
        }
        return new XctoResult(
            new SecurityItem("x-content-type-options", "X-Content-Type-Options", value, status),
            deduction
        );
    }

    private RpResult checkReferrerPolicyHeader(Map<String, String> headers) {
        String rpHeaderValue = headers.get("referrer-policy");
        String status = "success";
        String value = "header.configured";
        int deduction = 0;

        if (rpHeaderValue == null) {
            status = "warning";
            value = "header.notConfigured";
            deduction = SCORE_MISSING_OR_UNSAFE_RP;
        } else {
            List<String> secureValues = List.of("no-referrer", "same-origin", "strict-origin-when-cross-origin", "no-referrer-when-downgrade");
            boolean isSecure = secureValues.stream().anyMatch(rpHeaderValue::equalsIgnoreCase);

            if (isSecure) {
                value = rpHeaderValue.toLowerCase();
            } else {
                status = "warning";
                value = "header.referrer.unsafeValue:" + rpHeaderValue;
                deduction = SCORE_MISSING_OR_UNSAFE_RP;
            }
        }
        return new RpResult(
            new SecurityItem("referrer-policy", "Referrer-Policy", value, status),
            deduction
        );
    }

    private static class HstsResult {
        final SecurityItem item;
        final int deduction;
        HstsResult(SecurityItem item, int deduction) { this.item = item; this.deduction = deduction; }
    }
    private static class CspResult {
        final SecurityItem item;
        final int deduction;
        CspResult(SecurityItem item, int deduction) { this.item = item; this.deduction = deduction; }
    }
    private static class XfoResult {
        final SecurityItem item;
        final int deduction;
        XfoResult(SecurityItem item, int deduction) { this.item = item; this.deduction = deduction; }
    }
    private static class XctoResult {
        final SecurityItem item;
        final int deduction;
        XctoResult(SecurityItem item, int deduction) { this.item = item; this.deduction = deduction; }
    }
    private static class RpResult {
        final SecurityItem item;
        final int deduction;
        RpResult(SecurityItem item, int deduction) { this.item = item; this.deduction = deduction; }
    }
}