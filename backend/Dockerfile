FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

# Install Maven
RUN apk add --no-cache maven

COPY . .

# Build the project
RUN mvn clean package -DskipTests

EXPOSE 8080

CMD ["java","-jar","target/*.jar"]
