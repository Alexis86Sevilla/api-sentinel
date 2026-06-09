# Etapa 1: Construir el archivo .jar usando una imagen oficial de Maven
FROM maven:3.9.6-eclipse-temurin-21-alpine AS builder
WORKDIR /app
COPY . .
# Ahora usamos 'mvn' directo, sin el './mvnw'
RUN mvn clean package -DskipTests

# Etapa 2: Ejecutar la aplicación
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
ENTRYPOINT ["java", "-Xmx300m", "-Xss512k", "-jar", "app.jar"]