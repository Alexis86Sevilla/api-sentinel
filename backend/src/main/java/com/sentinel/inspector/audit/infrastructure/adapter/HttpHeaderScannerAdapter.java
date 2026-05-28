package com.sentinel.inspector.audit.infrastructure.adapter;

import com.sentinel.inspector.audit.domain.port.HeaderScanner;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

public class HttpHeaderScannerAdapter implements HeaderScanner {

    private final HttpClient httpClient;

    public HttpHeaderScannerAdapter() {
        this.httpClient = HttpClient.newBuilder().build();
    }

    @Override
    public Map<String, String> scanHeaders(URI targetUrl) {
        System.out.println("Scanning headers for URL: " + targetUrl.toString());

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(targetUrl)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            return response.headers().map().entrySet().stream()
                    .collect(Collectors.toMap(
                            entry -> entry.getKey(),
                            entry -> entry.getValue().get(0)
                    ));

        } catch (IOException | InterruptedException e) {
            System.err.println("Error during HTTP header scan for " + targetUrl + ": " + e.getMessage());
            return Collections.emptyMap();
        }
    }
}