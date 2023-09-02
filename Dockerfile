# Stage 1: Build the application
FROM maven:3.8.7 as build
WORKDIR /app

# Copy the source code and build the application
COPY . .
RUN mvn package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17

# Copy the JAR file from the build stage
COPY --from=build /app/gateway/target/*.jar /app.jar

# Expose the port that the application will run on (replace 8080 with your desired port)
EXPOSE 8080

# Start the application
CMD ["java", "-jar", "spring-boot:run", "app.jar"]