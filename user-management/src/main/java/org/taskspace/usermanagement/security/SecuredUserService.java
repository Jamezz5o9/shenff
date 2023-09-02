package org.taskspace.usermanagement.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.service.UserService;

import static java.lang.String.format;

@Service
@RequiredArgsConstructor
public class SecuredUserService implements UserDetailsService {
    private final UserService userService;

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        AppUser user = userService.findByEmailIgnoreCase(email).orElseThrow(
                () -> new UsernameNotFoundException(format("User not found with email %s", email)));
        return UserPrincipal.create(user);
    }
}