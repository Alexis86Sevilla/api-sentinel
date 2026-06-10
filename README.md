# API Sentinel

Analizador de seguridad web moderno y completo. Audita cualquier sitio web en segundos y obtén un informe detallado de vulnerabilidades, headers de seguridad, SSL/TLS, cookies y configuración del servidor.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Demo

[Security Analyzer](https://api-sentinel.pages.dev/)

## Características

- 🔒 **Análisis completo**: 5 categorías de seguridad auditadas
- ⚡ **Rápido**: Resultados en segundos con carga simultánea
- 🌍 **Multi-idioma**: Soporte Español/Inglés
- 📊 **Puntuación clara**: Score general + desglose detallado
- 📱 **Responsive**: Funciona en cualquier dispositivo
- 🎨 **UI moderna**: Tema oscuro con diseño elegante

## Arquitectura

El proyecto está dividido en dos partes:

```
api-sentinel/
├── backend/          # Spring Boot - API REST
│   ├── Java 21
│   ├── Spring Boot 3.x
│   └── Maven
│
└── frontend/         # Angular 21 - SPA
    ├── Angular 21
    ├── TypeScript
    └── Tailwind CSS
```

## Categorías Auditadas

| Categoría | Qué analiza |
|-----------|-------------|
| **Headers de Seguridad** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **SSL/TLS** | Certificado, protocolo, expiración, cipher suite |
| **Cookies** | Secure flag, HttpOnly, SameSite, cookies de terceros |
| **Vulnerabilidades** | Server version, clickjacking, XSS, SQL injection, dependencias |
| **Configuración** | HTTPS, redirección HTTP→HTTPS, compresión, listado de directorios |

## Quick Start

### Backend

```bash
cd backend
./mvnw spring-boot:run
```

API disponible en: `http://localhost:8080`

### Frontend

```bash
cd frontend
pnpm install
ng serve
```

App disponible en: `http://localhost:4200`

## Documentación

- [Backend README](backend/README.md)
- [Frontend README](frontend/README.md)

## API Endpoints

### POST `/api/audit`

Auditoría completa de seguridad.

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

## Autor

**Alexis García Mancha**
- Frontend Developer
- [LinkedIn](https://www.linkedin.com/in/alexis-gm/)
- [GitHub](https://github.com/Alexis86Sevilla)

## Licencia

MIT