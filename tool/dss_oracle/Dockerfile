# DSS oracle harness image. The DSS version is pinned in pom.xml (dss.version) and dss_version.txt.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src src
RUN mvn -B -q package -DskipTests
# The DSS default policy shipped in the pinned jar, and a variant with revocation
# availability ignored (our "no-revocation" policy: revocationDataAvailable = ignore).
RUN mkdir -p /out/policy \
 && mkdir /tmp/pj \
 && (cd /tmp/pj && jar xf /src/target/lib/dss-policy-jaxb-*.jar policy/constraint.xml) \
 && cp /tmp/pj/policy/constraint.xml /out/policy/default.xml \
 && sed -e 's/<RevocationDataAvailable Level="[A-Z]*"/<RevocationDataAvailable Level="IGNORE"/' \
        -e 's/<AcceptableRevocationDataFound Level="[A-Z]*"/<AcceptableRevocationDataFound Level="IGNORE"/' \
        /out/policy/default.xml > /out/policy/no-revocation.xml \
 && ! cmp -s /out/policy/default.xml /out/policy/no-revocation.xml

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /src/target/dss-oracle-0.1.0.jar /app/
COPY --from=build /src/target/lib /app/lib
COPY --from=build /out/policy /app/policy
COPY dss_version.txt /app/dss_version.txt
# Offline by design: run with --network none.
ENTRYPOINT ["java", "-cp", "/app/dss-oracle-0.1.0.jar:/app/lib/*", "oracle.Oracle"]
