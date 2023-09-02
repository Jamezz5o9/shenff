package org.taskspace.usermanagement.security;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface SecurityDetailRepository extends JpaRepository<SecurityDetail, Long> {
    @Query("select sd from SecurityDetail sd JOIN sd.user u where u.id = :userId")
    List<SecurityDetail> findByUserId(Long userId);
    Optional<SecurityDetail> findSecurityDetailByToken(String token);
}
