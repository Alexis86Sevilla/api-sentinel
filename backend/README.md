# API Sentinel

Servicio backend Spring Boot para análisis de seguridad web. Proporciona endpoints para auditar headers de seguridad, SSL/TLS, cookies, vulnerabilidades y configuración del servidor.

## Tecnologías

- Java 21
- Spring Boot 3.x
- Maven

## Estructura del Proyecto

```
src/main/java/com/sentinel/inspector/
├── audit/
│   ├── application/          # Casos de uso y servicios
│   ├── domain/               # Modelos y puertos (Hexagonal)
│   ├── controller/           # Controladores REST
│   └── infrastructure/       # Adaptadores e implementaciones
└── config/                   # Configuración CORS y otros
```

## API Endpoints

### POST `/api/audit`
Realiza auditoría completa de seguridad de una URL.

**Request:**
```json
{
  "url": "https://ejemplo.com"
}
```

**Response:**
```json
{
  "headers": { "score": 85, "items": [...] },
  "ssl": { "score": 100, "items": [...] },
  "cookies": { "score": 75, "items": [...] },
  "vulnerabilities": { "score": 90, "items": [...] },
  "serverConfig": { "score": 80, "items": [...] }
}
```

## Ejecutar Localmente

```bash
./mvnw spring-boot:run
```

El servidor iniciará en `http://localhost:8080`

## Compilar

```bash
./mvnw clean package
```

## Tests

```bash
./mvnw test
```

## Características Auditadas

- **Headers de Seguridad:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- **SSL/TLS:** Certificado, protocolo, expiración, cipher suite
- **Cookies:** Secure flag, HttpOnly, SameSite, cookies de terceros
- **Vulnerabilidades:** Versión del servidor expuesta, clickjacking, XSS, SQL injection, dependencias obsoletas
- **Configuración del Servidor:** HTTPS, redirección HTTP→HTTPS, compresión GZIP, listado de directorios