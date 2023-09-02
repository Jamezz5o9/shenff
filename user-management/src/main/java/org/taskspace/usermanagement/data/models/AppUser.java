package org.taskspace.usermanagement.data.models;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Setter
@Getter
@Entity(name = "app_user")
public class AppUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userId;

    private String email;

    private String password;

    private String name;

    private boolean isVerified;

    private String imageUrl;

    @Enumerated(EnumType.STRING)
    @JsonIgnore
    private AuthProvider provider;

    @JsonIgnore
    private String providerId;

    @OneToOne(fetch = FetchType.EAGER, targetEntity = Role.class)
    @JoinColumn(nullable = false, name = "role_id")
    private Role roles;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    @Column(name = "created_at", insertable = false, updatable = false)
    private LocalDate createdAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    @Column(name = "modified_at", insertable = false, updatable = false)
    private LocalDate modifiedAt;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm")
    @Column(name = "deleted_at", insertable = false, updatable = false)
    private LocalDate deletedAt;
}