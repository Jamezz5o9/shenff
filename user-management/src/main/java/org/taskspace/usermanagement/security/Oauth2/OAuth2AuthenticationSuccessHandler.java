package org.taskspace.usermanagement.security.Oauth2;

import jakarta.servlet.http.*;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.exception.TaskSpaceUserManagementException;
import org.taskspace.usermanagement.security.JwtService;
import org.taskspace.usermanagement.security.SecurityDetail;
import org.taskspace.usermanagement.security.SecurityDetailService;
import org.taskspace.usermanagement.security.UserPrincipal;
import org.taskspace.usermanagement.service.UserService;
import org.taskspace.usermanagement.utils.CookieUtils;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.taskspace.usermanagement.utils.ApplicationConstant.REDIRECT_URI_PARAM_COOKIE_NAME;

@RequiredArgsConstructor
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final SecurityDetailService securityDetailService;
    private final UserService userService;

    @Value("${app.oauth2.authorized-redirect-uris}")
    private List<String> authorizedRedirectUris;

    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    @SneakyThrows
    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new TaskSpaceUserManagementException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        String token = jwtService.generateToken(userPrincipal.getEmail());
        AppUser foundUser = userService.findByEmailIgnoreCase(userPrincipal.getEmail())
                .orElseThrow(()-> new TaskSpaceUserManagementException("User Not Found"));
        revokeAllUserToken(foundUser.getId());
        saveToken(token, foundUser);
        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("token", token)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequest(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);
        return authorizedRedirectUris
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    return authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort();
                });
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
}
