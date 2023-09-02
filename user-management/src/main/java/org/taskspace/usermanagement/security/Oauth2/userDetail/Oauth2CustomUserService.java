package org.taskspace.usermanagement.security.Oauth2.userDetail;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.taskspace.notificationmanagement.controller.NotificationController;
import org.taskspace.notificationmanagement.dto.request.NotificationRequest;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.AuthProvider;
import org.taskspace.usermanagement.data.models.Role;
import org.taskspace.usermanagement.data.repository.UserRepository;
import org.taskspace.usermanagement.exception.OAuth2AuthenticationProcessingException;
import org.taskspace.usermanagement.security.UserPrincipal;
import org.taskspace.usermanagement.service.RoleService;
import org.thymeleaf.context.Context;

import java.time.LocalDate;
import java.util.Optional;

import static org.taskspace.usermanagement.security.Oauth2.userDetail.OAuth2UserDataFactory.getOauth2UserData;
import static org.taskspace.usermanagement.utils.ApplicationConstant.TASK_SPACE_EMAIL;
import static org.taskspace.usermanagement.utils.utils.UserUtility.generateUserId;

@Service
@RequiredArgsConstructor
public class Oauth2CustomUserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final NotificationController controller;
    private final RoleService roleService;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        Oauth2UserData oauth2UserData = getOauth2UserData(userRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());

        if (oauth2UserData != null && oauth2UserData.getEmail() == null && oauth2UserData.getEmail().isEmpty()) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        assert oauth2UserData != null;
        Optional<AppUser> optionalUser = userRepository.findByEmailIgnoreCase(oauth2UserData.getEmail());
        AppUser user;
        if (optionalUser.isPresent()) {
            user = optionalUser.get();
            if (!user.getProvider().equals(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase()))) {
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                        user.getProvider().name().toUpperCase() + " account. Please use your " + user.getProvider().name().toUpperCase() +
                        " account to login.");
            }
            user = updateExistingUser(user, oauth2UserData);
        } else user = registerNewUser(oauth2UserData, userRequest);
        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private AppUser registerNewUser(Oauth2UserData oauth2UserData, OAuth2UserRequest userRequest) {
        Role foundRole = roleService.findUserRoleByName("USER");
        AppUser userToSave = new AppUser();
        userToSave.setVerified(true);
        userToSave.setEmail(oauth2UserData.getEmail());
        userToSave.setImageUrl(oauth2UserData.getImageUrl());
        userToSave.setName(oauth2UserData.getName());
        userToSave.setProvider(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId().toUpperCase()));
        userToSave.setProviderId(oauth2UserData.getUserId());
        userToSave.setUserId(generateUserId());
        userToSave.setRoles(foundRole);
        userToSave.setCreatedAt(LocalDate.now());
        sendWelcomeEmail(oauth2UserData.getEmail(), oauth2UserData.getName());
        return userRepository.save(userToSave);
    }

    private AppUser updateExistingUser(AppUser existingUser, Oauth2UserData oauth2UserData) {
        existingUser.setName(oauth2UserData.getName());
        existingUser.setImageUrl(oauth2UserData.getImageUrl());
        return userRepository.save(existingUser);
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
}