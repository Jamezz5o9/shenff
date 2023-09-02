# TaskSpace

The TaskSpace Application Backend is a comprehensive and robust backend solution built using Java 17, Spring Boot 3, Spring Security 6, PostgreSQL, and a Multi-Module Architecture. This backend powers a modern task management system, offering seamless task creation, organization, tracking, and notification functionalities. Leveraging OAuth2 implementation, it ensures secure authentication and authorization for users, along with modularization for efficient development and maintenance.

## Key Features

- Java 17: The backend is developed using the latest Java 17 features, ensuring high performance, improved memory management, and enhanced developer productivity.

- Spring Boot 3: Spring Boot 3 provides a strong foundation for building microservices with its streamlined development approach, embedded server, auto-configuration, and powerful dependency management.

- Spring Security 6: Implementing Spring Security 6 ensures robust security measures, including user authentication and authorization, role-based access control, and protection against common security vulnerabilities.

- PostgreSQL Database: The PostgreSQL database system is used to store and manage various data entities, such as user profiles, tasks, notifications, and more, ensuring data integrity and scalability.

- Multi-Module Architecture: The backend is structured into modular components, including User Management, Task Management, Notification, and Gateway modules. This approach promotes code reusability, maintainability, and easy scalability. 

- OAuth2 Implementation: The backend integrates OAuth2 for secure authentication and authorization. This allows users to use their existing accounts from Google, GitHub, or Facebook to log in, enhancing user convenience and security.

- RESTful APIs: The backend exposes a set of RESTful APIs that enable seamless communication between client applications and the server. These APIs provide endpoints for user management, task management, notifications, and more.

## Benefits

- Scalability: The modular architecture allows for easy scalability as new features can be added without disrupting existing components.

- Security: Spring Security 6 and OAuth2 ensure robust protection against unauthorized access, while PostgreSQL safeguards user data.

- Notification System: Automated Emails for Email verifications, Task reminders and Notifications.

- Flexibility: Spring Boot's flexibility and Spring Security's customization capabilities enable the adaptation of the backend to various application requirements.

- Performance: Java 17's performance enhancements and Spring Boot's optimized configuration contribute to excellent runtime performance.

- Documentation: Comprehensive API documentation using tools like Swagger/OpenAPI ensures clear communication between frontend and backend developers and simplifies the integration process.

The TaskSpace Application Backend offers a modern, secure, and user-friendly backend solution for task management. Leveraging cutting-edge technologies and architectural principles, it empowers businesses and users to efficiently manage tasks, enhance productivity, and stay organized.
<br>

## Technologies Used
- Java (Programming language)
- Springboot (Framework used to develop the APIs)
- Maven (Dependency manager)
- PostgreSQL (Database for data storage)
- JWT (Library for authentication)
- Render (Database Hosting service)
- Spring Security (Framework used for security)

## Prerequisites

To build and run this project, you'll need:

- Java JDK 17 or later
- Spring Boot 3.0
- Maven 3.0 or later

## Features

- User authentication and authorization using Spring Security 
- CRUD operations for managing tasks 
- PostgreSQL database integration 
- API documentation using Swagger 
- OAuth2 integration with github and google for secure authentication and authorization
- JWT-based token authentication

## Getting Started

To get started with TaskSpace, you will need to clone this repository to your local machine and set up the necessary dependencies.

### Installation

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/{Your userName}/taskspace.git
    ```

2. Create PostgreSQL database

   ```bash
   psql> create database taskspace
   ```

3. Configure database username and password

     ```properties
   # This is optional if you're testing the app in localhost. A demo database is already provided.
   # src/main/resources/application.yml
     spring:
       datasource:
         url: jdbc:postgresql://localhost:5432/taskspace
         username: <YOUR_DB_USERNAME>
         password: <YOUR_DB_PASSWORD>

     ```

4. specify OAuth2 Provider ClientIds and ClientSecrets 
- This is optional if you're testing the app in localhost. A demo clientId and clientSecret is already specified.

5.  Set up the backend server:
   ```bash
     mvn spring-boot:run
   ```

## OAUTH2 Authentication Endpoints

   ```bash
     (github) http://localhost:8080/auth/oauth2/authorize/github
     (google) http://localhost:8080/auth/oauth2/authorize/google
     
     The above endpoint Authenticates, Authorize, Persit and redirects to a link with a JWT token as as parameter which is used to make subsequent API call 
     
     http://localhost:8080/?token={token}
   ```

## Swagger Authentication Endpoints

   ```bash
     (Swagger) http://localhost:8080/swagger-ui/index.html#
     
     The above Url routes to the swagger UI for testing.
     The Authentication groups relates to Registering with Email, Password and name
     The Task Management group relates to the Basic CRUD operations for the case study
     http://localhost:8080/?token={token}
   ```

## Default DataBase Credentials

   ```bash
   To use the default database credentials, ensure you are connected to the internet
   username: taskspace_postgres
   database: taskspace_staging_dev 
   password: KWXV3j2ryLw0JSRk3Nr1PBuS9oVjRy8y
   host: dpg-cjjil3ephtvs73fb06fg-a.oregon-postgres.render.com
   port: 5432
   ```

## Functional requirement

- User story: I can register a new account
- User story: I can log in
- User story: I can log in or register with at least one of the following services: Google or Github
- User story: I can sign out
- User story: I can create a Task
- User Story: I can Update a created Task
- User Story: I can See All Created Task
- User Story: I can Delete Task

## Non-Functional Requirements

The following non-functional requirements must be met:

- Security: The application has robust security measures in place to protect user data and prevent unauthorized access.
- Availability: The application is highly available, with minimal downtime and interruptions in service.
- Performance: The application is optimized for low latency, with fast response times to user requests.