# Etapa 1: Construir el archivo .jar
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app
COPY . .
# Otorga permisos de ejecución al wrapper de Maven
RUN chmod +x mvnw
RUN ./mvnw clean package -DskipTests

# Etapa 2: Ejecutar la aplicación
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
# -Xmx300m asegura que Java no consuma todos los 512MB del servidor
ENTRYPOINT ["java", "-Xmx300m", "-Xss512k", "-jar", "app.jar"]