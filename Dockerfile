FROM eclipse-temurin:17-jdk-alpine
WORKDIR /app
COPY target/authentication_service-0.0.1.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]