export const SecurityTooltips: Record<string, { title: string; description: string; fix: string }> = {
  // Headers
  'strict-transport-security': {
    title: 'HSTS (HTTP Strict Transport Security)',
    description: 'Fuerza al navegador a usar siempre HTTPS, evitando ataques de downgrade.',
    fix: 'Agrega el header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
  },
  'content-security-policy': {
    title: 'Content Security Policy',
    description: 'Controla qué recursos puede cargar la página, previniendo XSS.',
    fix: 'Configura CSP con directivas seguras sin \'unsafe-inline\''
  },
  'x-frame-options': {
    title: 'X-Frame-Options',
    description: 'Previene que tu sitio sea embebido en iframes (clickjacking).',
    fix: 'Agrega: X-Frame-Options: DENY o SAMEORIGIN'
  },
  'x-content-type-options': {
    title: 'X-Content-Type-Options',
    description: 'Evita que el navegador "adivine" el tipo de contenido.',
    fix: 'Agrega: X-Content-Type-Options: nosniff'
  },
  'referrer-policy': {
    title: 'Referrer Policy',
    description: 'Controla qué información se envía al navegar a otros sitios.',
    fix: 'Agrega: Referrer-Policy: strict-origin-when-cross-origin'
  },
  // SSL
  'certificate': {
    title: 'Certificado SSL',
    description: 'Verifica la identidad del servidor y encripta la comunicación.',
    fix: 'Usa certificados de proveedores confiables (Let\'s Encrypt, etc.)'
  },
  'protocol': {
    title: 'Protocolo TLS',
    description: 'La versión del protocolo de seguridad utilizado.',
    fix: 'Configura TLS 1.2 o superior, deshabilita versiones viejas'
  },
  'expiration': {
    title: 'Expiración del Certificado',
    description: 'Tiempo restante antes de que el certificado deje de ser válido.',
    fix: 'Renueva el certificado antes de que expire'
  },
  'cipher': {
    title: 'Cifrado',
    description: 'Algoritmo utilizado para encriptar los datos.',
    fix: 'Usa cifrados fuertes como AES-256-GCM o ChaCha20-Poly1305'
  },
  // Cookies
  'secure': {
    title: 'Secure Flag',
    description: 'La cookie solo se envía por conexiones HTTPS.',
    fix: 'Agrega el atributo Secure a todas las cookies'
  },
  'httponly': {
    title: 'HttpOnly Flag',
    description: 'La cookie no es accesible desde JavaScript (protege contra XSS).',
    fix: 'Agrega el atributo HttpOnly a cookies de sesión'
  },
  'samesite': {
    title: 'SameSite Attribute',
    description: 'Controla si la cookie se envía en solicitudes cross-site.',
    fix: 'Usa SameSite=Strict o SameSite=Lax para cookies de sesión'
  },
  'thirdparty': {
    title: 'Cookies de Terceros',
    description: 'Cookies establecidas por dominios diferentes al de la página.',
    fix: 'Minimiza el uso de cookies de terceros o consigue consentimiento explícito'
  },
  // Vulnerabilities
  'server-version': {
    title: 'Versión del Servidor',
    description: 'Si se expone la versión del servidor, atacantes pueden buscar vulnerabilidades conocidas.',
    fix: 'Oculta la versión del servidor en los headers HTTP'
  },
  'clickjacking': {
    title: 'Protección contra Clickjacking',
    description: 'Previene que tu sitio sea embebido en iframes maliciosos.',
    fix: 'Implementa X-Frame-Options o CSP frame-ancestors'
  },
  'xss': {
    title: 'Protección XSS',
    description: 'Medidas contra Cross-Site Scripting.',
    fix: 'Implementa CSP, sanitiza inputs, usa HttpOnly cookies'
  },
  'sql-injection': {
    title: 'Protección SQL Injection',
    description: 'Prevención de inyección de código SQL.',
    fix: 'Usa consultas parametrizadas, ORMs, valida inputs'
  },
  'dependencies': {
    title: 'Dependencias Obsoletas',
    description: 'Librerías desactualizadas con vulnerabilidades conocidas.',
    fix: 'Mantén dependencias actualizadas con herramientas como Dependabot'
  },
  // Server Config
  'https': {
    title: 'HTTPS Habilitado',
    description: 'El sitio está disponible mediante conexión segura.',
    fix: 'Configura certificados SSL/TLS para tu dominio'
  },
  'redirect': {
    title: 'Redirección HTTP a HTTPS',
    description: 'Redirige automáticamente tráfico HTTP a HTTPS.',
    fix: 'Configura redirecciones 301 de HTTP a HTTPS'
  },
  'compression': {
    title: 'Compresión GZIP',
    description: 'Reduce el tamaño de las respuestas para mejorar velocidad.',
    fix: 'Habilita compresión gzip/deflate en el servidor'
  },
  'directory-listing': {
    title: 'Listado de Directorios',
    description: 'Si está habilitado, muestra contenido de carpetas.',
    fix: 'Deshabilita directory listing en la configuración del servidor'
  }
};
