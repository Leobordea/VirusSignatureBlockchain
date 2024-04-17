plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("org.hyperledger.fabric:fabric-gateway:1.5.0")
    compileOnly("io.grpc:grpc-api:1.63.0")
    runtimeOnly("io.grpc:grpc-netty-shaded:1.63.0")
    implementation("com.google.code.gson:gson:2.10.1")
}

tasks.test {
    useJUnitPlatform()
}