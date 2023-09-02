package org.taskspace.usermanagement.security.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@OpenAPIDefinition(servers = {@Server(url = "/", description = "Default Server URL")})
@Configuration
@SecurityScheme(name = "BearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT")
public class OpenApiConfig {
    Contact lekan = new Contact()
            .name("Lekan Sofuyi")
            .email("lekan.sofuyi@outlook.com")
            .url("https://github.com/ola-lekan01");

    @Bean
    public OpenAPI configAPI(){
        return new OpenAPI()
                .info(new Info()
                        .title("Task Space Api")
                        .version("Version 1.00")
                        .description("The Spring Boot Task Application is a lightweight and efficient project " +
                                "designed to manage and organize tasks or to-do lists. Built using the Spring Boot " +
                                "framework, this application provides a simple and intuitive application programming " +
                                "interface for users to create, read, update delete, and track their tasks in a convenient manner.")
                        .contact(lekan)
                        .termsOfService("Coming Soon!!! "));
    }
}