FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

RUN apk add --no-cache maven

# copy only backend code
COPY . .

# go inside backend folder where pom.xml exists
WORKDIR /app/backend

RUN mvn clean package -DskipTests

EXPOSE 8080

CMD ["java","-jar","target/projectmanagement-0.0.1-SNAPSHOT.jar"]
