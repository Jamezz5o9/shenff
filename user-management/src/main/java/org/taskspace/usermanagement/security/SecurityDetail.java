package org.taskspace.usermanagement.security;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.taskspace.usermanagement.data.models.AppUser;

@Entity
@Setter
@Getter
public class SecurityDetail {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 500)
    private String token;

    @OneToOne
    private AppUser user;

    private boolean isRevoked;

    private boolean isExpired;
}

