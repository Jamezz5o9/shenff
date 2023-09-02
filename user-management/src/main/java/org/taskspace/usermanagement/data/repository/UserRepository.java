package org.taskspace.usermanagement.data.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.taskspace.usermanagement.data.models.AppUser;

import java.util.Optional;

public interface UserRepository extends JpaRepository<AppUser, String> {
    @Query("SELECT u FROM app_user u WHERE LOWER(u.email) = LOWER(:email)")
    Optional<AppUser> findByEmailIgnoreCase(String email);

    Boolean existsByEmail(String email);
}
