FROM maven:3-amazoncorretto-8 AS dependencies
COPY pom.xml /build/
WORKDIR /build/
RUN mvn --batch-mode dependency:go-offline dependency:resolve-plugins

FROM maven:3-amazoncorretto-8 AS build
COPY --from=dependencies /root/.m2 /root/.m2
COPY pom.xml /build/
COPY src /build/src
WORKDIR /build/
RUN mvn -P dockerfile --batch-mode --fail-fast package


FROM amazoncorretto:8-alpine-jdk AS runtime
WORKDIR /app
COPY --from=build /build/target/application.jar /app/application.jar
ENTRYPOINT ["java"]
CMD ["-jar", "/app/application.jar"]