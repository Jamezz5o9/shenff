package org.taskspace.usermanagement.service;

import org.taskspace.usermanagement.data.dto.request.LoginRequest;
import org.taskspace.usermanagement.data.dto.request.TokenRefreshRequest;
import org.taskspace.usermanagement.data.dto.request.UserRequest;
import org.taskspace.usermanagement.data.dto.response.TokenResponse;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.Token;

public interface AuthService {
    AppUser registerNewUserAccount(UserRequest userRequest);
    void confirmVerificationToken(String verificationToken);
    Token createVerificationToken(AppUser user, String tokenType);
    TokenResponse login(LoginRequest loginRequest);
    TokenResponse refreshToken(TokenRefreshRequest request);
    AppUser findUserByEmail(String email);
}