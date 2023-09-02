package org.taskspace.usermanagement.data.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.taskspace.usermanagement.data.models.AppUser;
import org.taskspace.usermanagement.data.models.Token;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByTokenAndTokenType(String token, String tokenType);

    Optional<Token> findByUser(AppUser user);
}
