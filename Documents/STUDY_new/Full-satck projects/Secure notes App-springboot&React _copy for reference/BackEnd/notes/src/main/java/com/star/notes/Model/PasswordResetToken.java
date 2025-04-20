package com.star.notes.Model;


import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;

@Entity
@Data
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false,unique = true)
    private String token;

    @Column(nullable = false)
    private Instant expiresDate;

    @Column(nullable = false)
    private boolean used;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public PasswordResetToken(String token, Instant expiryDate, User user) {
        this.token = token;
        this.expiresDate = expiryDate;
        this.user = user;
    }

    public PasswordResetToken() {

    }
}
