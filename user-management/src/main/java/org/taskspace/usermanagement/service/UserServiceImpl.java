package org.taskspace.usermanagement.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.repository.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public Optional<AppUser> findByEmailIgnoreCase(String email) {
        return userRepository.findByEmailIgnoreCase(email);
    }
}