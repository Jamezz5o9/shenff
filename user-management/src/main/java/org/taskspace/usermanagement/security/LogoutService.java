package org.taskspace.usermanagement.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
public class LogoutService implements LogoutHandler {

    private final SecurityDetailService securityDetailService;

    public LogoutService(
            SecurityDetailService securityDetailService) {
        this.securityDetailService = securityDetailService;
    }

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {

        String authHeader = request.getHeader("Authorization");
        String jwt;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) return;

        jwt = authHeader.substring(7);

        SecurityDetail foundSecurityDetail = securityDetailService.findSecurityDetailByToken(jwt);
        if (foundSecurityDetail != null) {
            foundSecurityDetail.setExpired(true);
            foundSecurityDetail.setRevoked(true);

            securityDetailService.save(foundSecurityDetail);
        }
    }
}
