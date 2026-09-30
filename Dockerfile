# Multi-stage build for the patched XPayLabs Java services.
# Builds all Spring Boot jars and packages the single image used by the 5 Java containers.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY . .
RUN mvn -q -B -DskipTests -Dmaven.test.skip=true package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/XPayLabs/target/XPayLabs.jar .
COPY --from=build /src/XPayLabs-merchant/target/XPayLabs-merchant.jar .
COPY --from=build /src/XPayLabs-eth/target/XPayLabs-eth.jar .
COPY --from=build /src/XPayLabs-tron/target/XPayLabs-tron.jar .
COPY --from=build /src/XPayLabs-sui/target/XPayLabs-sui.jar .
