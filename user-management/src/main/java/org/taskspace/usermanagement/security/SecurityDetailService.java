package org.taskspace.usermanagement.security;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityDetailService {
    private final SecurityDetailRepository securityDetailRepository;

    public List<SecurityDetail> findSecurityDetailByUserId(Long userId){
        return securityDetailRepository
                .findByUserId(userId);
    }
    public SecurityDetail findSecurityDetailByToken(String token){
        return securityDetailRepository
                .findSecurityDetailByToken(token)
                .orElse(null);
    }

    public void save(SecurityDetail securityDetail){
        securityDetailRepository.save(securityDetail);
    }
}
