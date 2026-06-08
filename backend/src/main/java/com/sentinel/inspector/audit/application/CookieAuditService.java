package com.sentinel.inspector.audit.application;

import com.sentinel.inspector.audit.domain.model.SecurityAuditResult;
import com.sentinel.inspector.audit.domain.model.SecurityItem;
import org.springframework.stereotype.Service;

import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class CookieAuditService {

    public SecurityAuditResult auditCookies(String url) {
        List<SecurityItem> items = new ArrayList<>();
        int score = 100;

        try {
            HttpClient client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager())
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Extraer cookies de los headers Set-Cookie
            List<String> setCookieHeaders = response.headers().allValues("Set-Cookie");
            List<HttpCookie> cookies = new ArrayList<>();
            
            for (String cookieHeader : setCookieHeaders) {
                try {
                    List<HttpCookie> parsedCookies = HttpCookie.parse(cookieHeader);
                    cookies.addAll(parsedCookies);
                } catch (Exception e) {
                    // Ignorar cookies mal formadas
                }
            }

            if (cookies.isEmpty()) {
                // No hay cookies - es bueno para seguridad
                items.add(new SecurityItem("secure", "label.secure", "cookie.noCookies", "valid"));
                items.add(new SecurityItem("httponly", "label.httponly", "cookie.noCookies", "valid"));
                items.add(new SecurityItem("samesite", "label.samesite", "cookie.noCookies", "valid"));
                items.add(new SecurityItem("thirdparty", "label.thirdparty", "cookie.detectedCount:0", "valid"));
                return new SecurityAuditResult(100, items);
            }

            // Analizar Secure Flag
            boolean allSecure = cookies.stream().allMatch(HttpCookie::getSecure);
            int secureScore = allSecure ? 0 : -25;
            score += secureScore;
            items.add(new SecurityItem(
                "secure",
                "label.secure",
                allSecure ? "cookie.enabled" : "cookie.disabled",
                allSecure ? "valid" : "error"
            ));

            // Analizar HttpOnly
            boolean allHttpOnly = cookies.stream().allMatch(cookie ->
                cookie.toString().toLowerCase().contains("httponly")
            );
            int httpOnlyScore = allHttpOnly ? 5 : -20;
            score += httpOnlyScore;
            items.add(new SecurityItem(
                "httponly",
                "label.httponly",
                allHttpOnly ? "cookie.enabled" : "cookie.disabled",
                allHttpOnly ? "valid" : "warning"
            ));

            // Analizar SameSite
            SameSiteAnalysis sameSiteAnalysis = analyzeSameSite(cookies);
            score += sameSiteAnalysis.score;
            items.add(new SecurityItem(
                "samesite",
                "label.samesite",
                sameSiteAnalysis.value,
                sameSiteAnalysis.status
            ));

            // Contar cookies de terceros
            int thirdPartyCount = countThirdPartyCookies(cookies, url);
            int thirdPartyScore = thirdPartyCount == 0 ? 5 : thirdPartyCount > 5 ? -25 : -10;
            score += thirdPartyScore;
            items.add(new SecurityItem(
                "thirdparty",
                "label.thirdparty",
                "cookie.detectedCount:" + thirdPartyCount,
                thirdPartyCount == 0 ? "valid" : thirdPartyCount > 5 ? "error" : "warning"
            ));

        } catch (Exception e) {
            score = 0;
            items.add(new SecurityItem("secure", "label.secure", "cookie.error:" + e.getMessage(), "error"));
            items.add(new SecurityItem("httponly", "label.httponly", "cookie.notAvailable", "error"));
            items.add(new SecurityItem("samesite", "label.samesite", "cookie.notAvailable", "error"));
            items.add(new SecurityItem("thirdparty", "label.thirdparty", "cookie.error", "error"));
        }

        score = Math.max(0, Math.min(100, score));
        return new SecurityAuditResult(score, items);
    }

    private SameSiteAnalysis analyzeSameSite(List<HttpCookie> cookies) {
        long strictCount = cookies.stream()
            .filter(c -> c.toString().toLowerCase().contains("samesite=strict"))
            .count();
        long laxCount = cookies.stream()
            .filter(c -> c.toString().toLowerCase().contains("samesite=lax"))
            .count();
        long noneCount = cookies.stream()
            .filter(c -> c.toString().toLowerCase().contains("samesite=none"))
            .count();
        long missingCount = cookies.size() - strictCount - laxCount - noneCount;

        if (strictCount == cookies.size()) {
            return new SameSiteAnalysis("cookie.strict", "valid", 10);
        } else if (strictCount + laxCount == cookies.size()) {
            return new SameSiteAnalysis("cookie.laxMixed", "valid", 5);
        } else if (noneCount > 0) {
            return new SameSiteAnalysis("cookie.noneInsecure", "error", -30);
        } else if (missingCount > 0) {
            return new SameSiteAnalysis("cookie.missingAttribute", "warning", -15);
        } else {
            return new SameSiteAnalysis("cookie.lax", "valid", 0);
        }
    }

    private int countThirdPartyCookies(List<HttpCookie> cookies, String url) {
        try {
            URI uri = URI.create(url);
            String domain = uri.getHost();
            if (domain == null) return 0;

            // Simplificación: cookies de terceros son las que tienen dominio diferente
            return (int) cookies.stream()
                .filter(cookie -> {
                    String cookieDomain = cookie.getDomain();
                    if (cookieDomain == null || cookieDomain.isEmpty()) {
                        return false; // Cookie de primera parte por defecto
                    }
                    // Si el dominio de la cookie no coincide con el dominio de la URL
                    String normalizedDomain = domain.startsWith("www.") ? domain.substring(4) : domain;
                    String normalizedCookieDomain = cookieDomain.startsWith(".") ? cookieDomain.substring(1) : cookieDomain;
                    return !normalizedDomain.endsWith(normalizedCookieDomain) && 
                           !normalizedCookieDomain.endsWith(normalizedDomain);
                })
                .count();
        } catch (Exception e) {
            return 0;
        }
    }

    private record SameSiteAnalysis(String value, String status, int score) {}
}