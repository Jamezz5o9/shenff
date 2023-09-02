package org.taskspace.usermanagement.service;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.taskspace.notificationmanagement.controller.NotificationController;
import org.taskspace.notificationmanagement.dto.request.NotificationRequest;
import org.taskspace.usermanagement.data.dto.request.LoginRequest;
import org.taskspace.usermanagement.data.dto.request.TokenRefreshRequest;
import org.taskspace.usermanagement.data.dto.request.UserRequest;
import org.taskspace.usermanagement.data.dto.response.TokenResponse;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.Role;
import org.taskspace.usermanagement.data.models.Token;
import org.taskspace.usermanagement.data.repository.TokenRepository;
import org.taskspace.usermanagement.data.repository.UserRepository;
import org.taskspace.usermanagement.exception.AuthException;
import org.taskspace.usermanagement.security.JwtService;
import org.taskspace.usermanagement.security.SecurityDetail;
import org.taskspace.usermanagement.security.SecurityDetailService;
import org.thymeleaf.context.Context;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static java.lang.String.format;
import static org.taskspace.usermanagement.data.models.AuthProvider.LOCAL;
import static org.taskspace.usermanagement.data.models.TokenType.REFRESH;
import static org.taskspace.usermanagement.data.models.TokenType.VERIFICATION;
import static org.taskspace.usermanagement.utils.ApplicationConstant.EXPIRATION;
import static org.taskspace.usermanagement.utils.ApplicationConstant.TASK_SPACE_EMAIL;
import static org.taskspace.usermanagement.utils.utils.UserUtility.generateUserId;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final ModelMapper modelMapper;
    private final PasswordEncoder passwordEncoder;
    private final TokenRepository tokenRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final SecurityDetailService securityDetailService;
    private final NotificationController controller;
    private final RoleService roleService;


    @Transactional
    public AppUser registerNewUserAccount(UserRequest userRequest) {
        if (Boolean.TRUE.equals(userRepository.existsByEmail(userRequest.getEmail()))) {
            throw new AuthException("Email is already in use");
        }

        Role foundRole = roleService.findUserRoleByName("USER");
        AppUser user = modelMapper.map(userRequest, AppUser.class);
        user.setRoles(foundRole);
        user.setCreatedAt(LocalDate.now());
        user.setUserId(generateUserId());
        user.setProvider(LOCAL);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return saveAUser(user);
    }

    @Override
    public void confirmVerificationToken(String verificationToken) {
        Token token = getAToken(verificationToken, VERIFICATION.toString());

        if (!isValidToken(token.getExpiryDate()))
            throw new AuthException("Token has expired");

        AppUser user = token.getUser();
        user.setVerified(true);
        saveAUser(user);
        sendWelcomeEmail(user.getEmail(), user.getName());
        tokenRepository.delete(token);
    }

    @Override
    public Token createVerificationToken(AppUser user, String tokenType) {
        String token = UUID.randomUUID().toString();
        Optional<Token> optionalToken = tokenRepository.findByUser(user);
        Token verificationToken;
        if (optionalToken.isPresent()) {
            verificationToken = optionalToken.get();
            verificationToken.setToken(token);
            verificationToken.setTokenType(tokenType);
            verificationToken.setExpiryDate(LocalDateTime.now().plusHours(EXPIRATION));
        } else verificationToken = new Token(token, user, tokenType);
        return tokenRepository.save(verificationToken);
    }


    @Transactional
    @Override
    public TokenResponse login(LoginRequest loginRequest)  {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AppUser user = findUserByEmail(loginRequest.getEmail());
        String jwtToken = jwtService.generateToken(user.getEmail());
        revokeAllUserToken(user.getId());
        saveToken(jwtToken, user);
        TokenResponse tokenResponse = new TokenResponse();
        Optional<Token> optionalToken = tokenRepository.findByUser(user);

        if (optionalToken.isPresent() && isValidToken(optionalToken.get().getExpiryDate())) {
            tokenResponse.setRefreshToken(optionalToken.get().getToken());
        } else if (optionalToken.isPresent() && !isValidToken(optionalToken.get().getExpiryDate())) {
            Token token = optionalToken.get();
            token.updateToken(UUID.randomUUID().toString(), REFRESH.name());
            tokenResponse.setRefreshToken(tokenRepository.save(token).getToken());
        } else {
            Token refreshToken = new Token(user);
            tokenResponse.setRefreshToken(tokenRepository.save(refreshToken).getToken());
        }
        tokenResponse.setJwtToken(jwtToken);
        tokenResponse.setEmail(user.getEmail());
        return tokenResponse;
    }

    @Override
    public TokenResponse refreshToken(TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();
        Optional<Token> refreshToken = tokenRepository.findByTokenAndTokenType(requestRefreshToken, REFRESH.toString());
        if (refreshToken.isPresent()) {
            Token token = getRefreshToken(refreshToken.get());
            String jwtToken = jwtService.generateToken(refreshToken.get().getUser().getEmail());
            return new TokenResponse(jwtToken, requestRefreshToken, token.getUser().getEmail());
        } else throw new AuthException("Invalid refresh token");
    }

    @Override
    public AppUser findUserByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new AuthException(format("user with email %s not found", email)));
    }

    private Token getRefreshToken(Token token) {
        if (isValidToken(token.getExpiryDate()))
            return token;
        else throw new AuthException("Refresh token was expired. Please make a new sign in request");
    }

    private boolean isValidToken(LocalDateTime expiryDate) {
        long minutes = ChronoUnit.MINUTES.between(LocalDateTime.now(), expiryDate);
        return minutes >= 0;
    }

    private void sendWelcomeEmail(String email, String name){
        NotificationRequest request = new NotificationRequest();
        Context context = new Context();
        context.setVariable("userName", name);
        request.setTo(email);
        request.setSubject("Welcome to TaskSpace");
        request.setContent("ThankYou");
        request.setContext(context);
        request.setSender(TASK_SPACE_EMAIL);
        controller.sendEmail(request);
    }

    private void saveToken(String jwt, AppUser user) {
        SecurityDetail securityDetail = new SecurityDetail();
        securityDetail.setToken(jwt);
        securityDetail.setExpired(false);
        securityDetail.setRevoked(false);
        securityDetail.setUser(user);
        securityDetailService.save(securityDetail);
    }

    private void revokeAllUserToken(Long userId) {
        var allUsersToken = securityDetailService.findSecurityDetailByUserId(userId);
        if (allUsersToken.isEmpty()) return;
        allUsersToken
                .forEach(securityDetail -> {
                    securityDetail.setRevoked(true);
                    securityDetail.setExpired(true);
                    securityDetailService.save(securityDetail);
                });
    }

    private Token getAToken(String token, String tokenType) {
        return tokenRepository.findByTokenAndTokenType(token, tokenType)
                .orElseThrow(() -> new AuthException("Invalid token"));
    }

    private AppUser saveAUser(AppUser user) {
        return userRepository.save(user);
    }

}