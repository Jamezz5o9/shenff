package org.taskspace.gateway.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.hateoas.Link;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.taskspace.gateway.response.ApiResponse;
import org.taskspace.notificationmanagement.controller.NotificationController;
import org.taskspace.notificationmanagement.dto.request.NotificationRequest;
import org.taskspace.usermanagement.controller.UserManagementAuthController;
import org.taskspace.usermanagement.data.dto.request.LoginRequest;
import org.taskspace.usermanagement.data.dto.request.TokenRefreshRequest;
import org.taskspace.usermanagement.data.dto.request.UserRequest;
import org.taskspace.usermanagement.data.dto.response.TokenResponse;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.Token;
import org.thymeleaf.context.Context;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;
import static org.taskspace.usermanagement.data.models.TokenType.VERIFICATION;
import static org.taskspace.usermanagement.utils.ApplicationConstant.TASK_SPACE_EMAIL;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Tag(name = "Task Space Authentication Management", description = "Endpoints for managing all user Authentications")
public class GatewayAuthenticationController {

    private final UserManagementAuthController authController;

    private final NotificationController notificationController;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> registerNewUser(@RequestBody @Valid UserRequest request) {
        AppUser user = authController.registerNewUser(request);
        generateVerificationToken(user);
        return new ResponseEntity<>(new ApiResponse
                (true, "Registration Successful and Pending verification, " +
                        "Please check your email for activation Link"), HttpStatus.CREATED);
    }

    @PostMapping("/resend-verification-token")
    public ResponseEntity<ApiResponse> resendVerificationToken(@RequestParam("email") String email){
        AppUser user = authController.findUserByEmail(email);
        generateVerificationToken(user);
        return new ResponseEntity<>(new ApiResponse
                (true, "Verification Link sent to Email"), HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authController.login(loginRequest));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        TokenResponse tokenResponse = authController.refreshToken(request);
        return new ResponseEntity<>(new ApiResponse (true, tokenResponse), HttpStatus.OK);
    }

    @GetMapping("/verify")
    public ResponseEntity<ApiResponse> verifyUser(@RequestParam("token") String token) {
        authController.confirmVerificationToken(token);
        return new ResponseEntity<>(new ApiResponse
                (true, "User is successfully verified, Please Login to Continue"), HttpStatus.OK);
    }

    private void sendVerificationEmail(String email, String name, String verificationLink) {
        NotificationRequest request = new NotificationRequest();
        Context context = new Context();
        context.setVariable("userName", name);
        context.setVariable("verificationLink", verificationLink);
        request.setTo(email);
        request.setSubject("Welcome to TaskSpace");
        request.setContent("welcome");
        request.setContext(context);
        request.setSender(TASK_SPACE_EMAIL);
        notificationController.sendEmail(request);
    }

    private void generateVerificationToken(AppUser user) {
        Token token = authController.createVerificationToken(user, VERIFICATION.toString());
        ResponseEntity<?> methodLinkBuilder = methodOn(GatewayAuthenticationController.class).verifyUser(token.getToken());
        Link verificationLink = linkTo(methodLinkBuilder).withRel("user-verification");
        sendVerificationEmail(user.getEmail(), user.getName(), verificationLink.getHref());
    }
}