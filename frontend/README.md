# API Sentinel

Frontend Angular 21 para el analizador de seguridad web. Interfaz moderna y responsive para auditar la seguridad de cualquier sitio web.

## Demo

[Security Analyzer](https://api-sentinel.pages.dev/)

## Características

- 🔒 Análisis de seguridad completo en segundos
- 🌍 Soporte multi-idioma (Español/Inglés)
- 📊 Puntuación general y desglose por categorías
- 🎨 Interfaz moderna con tema oscuro
- 📱 Totalmente responsive
- ⚡ Carga simultánea de todos los análisis

## Tecnologías

- Angular 21
- TypeScript
- Tailwind CSS

## Estructura

```
src/app/
├── components/
│   ├── home/                 # Página principal
│   │   ├── card/            # Cards de resultados
│   │   ├── security-score/  # Puntuación general
│   │   └── loading-spinner/ # Indicador de carga
│   ├── footer/              # Footer con info del autor
│   └── language-selector/   # Selector de idioma
├── services/
│   ├── api-url-audit.ts     # Servicio de API
│   └── i18n.service.ts      # Internacionalización
└── assets/
    └── i18n/                # Archivos de traducción
```

## Instalación

```bash
cd frontend
pnpm install
```

## Desarrollo

```bash
ng serve
```

Abrir `http://localhost:4200`

## Build

```bash
ng build --configuration production
```

## Características Implementadas

### Categorías de Análisis

1. **Headers de Seguridad** - HSTS, CSP, X-Frame-Options, etc.
2. **SSL/TLS** - Certificado, protocolo, expiración, cifrado
3. **Cookies** - Secure, HttpOnly, SameSite
4. **Vulnerabilidades** - Clickjacking, XSS, SQL Injection
5. **Configuración del Servidor** - HTTPS, compresión, etc.

### Internacionalización

Las traducciones están en `src/assets/i18n/`:
- `es.json` - Español
- `en.json` - Inglés

### UI/UX

- Tema oscuro con gradientes
- Animaciones suaves
- Tooltips informativos
- Estados de carga
- Validación de URL en tiempo real

## Licencia

MIT