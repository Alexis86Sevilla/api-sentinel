package com.sentinel.inspector.audit.domain.model;

public record SecurityItem(
    String key,
    String label,
    String value,
    String status
) {}