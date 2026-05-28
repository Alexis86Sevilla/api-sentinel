package com.sentinel.inspector.audit.domain.model;

import java.util.List;

public record SecurityAuditResult(
    int score,
    List<SecurityItem> items
) {}