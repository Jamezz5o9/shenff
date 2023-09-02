package org.taskspace.usermanagement.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.taskspace.usermanagement.data.dto.request.LoginRequest;
import org.taskspace.usermanagement.data.dto.request.TokenRefreshRequest;
import org.taskspace.usermanagement.data.dto.request.UserRequest;
import org.taskspace.usermanagement.data.dto.response.TokenResponse;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.Token;
import org.taskspace.usermanagement.service.AuthService;

@Component
@RequiredArgsConstructor
public class UserManagementAuthController {

    private final AuthService authService;

    public AppUser registerNewUser(UserRequest request) {
        return authService.registerNewUserAccount(request);
    }

    public Token createVerificationToken(AppUser user, String tokenType){
        return authService.createVerificationToken(user, tokenType);
    }
    public TokenResponse login(LoginRequest loginRequest) {
        return authService.login(loginRequest);
    }

    public void confirmVerificationToken(String verificationToken) {
        authService.confirmVerificationToken(verificationToken);
    }

    public TokenResponse refreshToken(TokenRefreshRequest request){
        return authService.refreshToken(request);
    }

    public AppUser findUserByEmail(String email) {
        return authService.findUserByEmail(email);
    }

}