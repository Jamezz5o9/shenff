package org.taskspace.usermanagement.service;

import org.taskspace.usermanagement.data.models.AppUser;

import java.util.Optional;

public interface UserService {
    Optional<AppUser> findByEmailIgnoreCase(String email);
}
