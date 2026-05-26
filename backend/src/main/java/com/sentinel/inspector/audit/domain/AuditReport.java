package com.sentinel.inspector.audit.domain;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public record AuditReport(
    String targetUrl,
    LocalDateTime timestamp,
    Map<String, String> headers,
    List<String> issues,
    int score
) {}
