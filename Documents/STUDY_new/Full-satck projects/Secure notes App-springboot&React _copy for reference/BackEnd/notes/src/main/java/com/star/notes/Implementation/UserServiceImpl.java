package com.star.notes.Implementation;



import com.star.notes.DTOs.UserDTO;
import com.star.notes.Model.AppRole;
import com.star.notes.Model.PasswordResetToken;
import com.star.notes.Model.Role;
import com.star.notes.Model.User;
import com.star.notes.Repository.PasswordResetTokenRepo;
import com.star.notes.Repository.RoleRepo;
import com.star.notes.Repository.UserRepo;
import com.star.notes.Service.UserService;
import com.star.notes.Util.EmailService;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    @Value("${frontend.url}")
    String frontendUrl;
    @Autowired
    UserRepo userRepository;

    @Autowired
    RoleRepo roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    PasswordResetTokenRepo passwordResetTokenRepo;

    @Autowired
    EmailService emailService;

    @Autowired
    TotpServiceImpl totpService;



    @Override
    public void updateUserRole(Long userId, String roleName) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        AppRole appRole = AppRole.valueOf(roleName);
        Role role = roleRepository.findByRoleName(appRole)
                .orElseThrow(() -> new RuntimeException("Role not found"));
        user.setRole(role);
        userRepository.save(user);
    }


    @Override
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }


    @Override
    public UserDTO getUserById(Long id) {
//        return userRepository.findById(id).orElseThrow();
        User user = userRepository.findById(id).orElseThrow();
        return convertToDto(user);
    }

    private UserDTO convertToDto(User user) {
        return new UserDTO(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.getTwoFactorSecret(),
                user.isTwoFactorEnabled(),
                user.getSignUpMethod(),
                user.getRole(),
                user.getCreatedDate(),
                user.getUpdatedDate()
        );
    }

    @Override
    public User findByUsername(String username) {
        Optional<User> user = userRepository.findByUserName(username);
        return user.orElseThrow(() -> new RuntimeException("User not found with username: " + username));
    }


    @Override
    public void updateAccountLockStatus(Long userId, boolean lock) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonLocked(!lock);
        userRepository.save(user);
    }

    @Override
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @Override
    public void updateAccountExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setAccountNonExpired(!expire);
        userRepository.save(user);
    }

    @Override
    public void updateAccountEnabledStatus(Long userId, boolean enabled) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setEnabled(enabled);
        userRepository.save(user);
    }

    @Override
    public void updateCredentialsExpiryStatus(Long userId, boolean expire) {
        User user = userRepository.findById(userId).orElseThrow(()
                -> new RuntimeException("User not found"));
        user.setCredentialsNonExpired(!expire);
        userRepository.save(user);
    }


    @Override
    public void updatePassword(Long userId, String password) {
        try {
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));
            user.setPassword(passwordEncoder.encode(password));
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException("Failed to update password");
        }
    }

    @Override
    public void generatePasswordResetToken(String email){
        User user=userRepository.findByEmail(email).
                orElseThrow(()->new RuntimeException("user not found"));

   String token = UUID.randomUUID().toString();

   Instant expiryDate=Instant.now().plus(24, ChronoUnit.HOURS);//within 24 hours password needs to be reseted

        PasswordResetToken passwordResetToken=new PasswordResetToken(token,expiryDate,user);

        passwordResetTokenRepo.save(passwordResetToken);

        String resetUrl=frontendUrl+"/reset-password?token="+token;
        //sent email to user
        emailService.sendPasswordResetEmail(user.getEmail(), resetUrl);
    }

    @Override
    public void reserPassword(String token, String password) {
        PasswordResetToken passwordResetToken=passwordResetTokenRepo.
                findByToken(token).orElseThrow(()->new RuntimeException("Invalid reset token"));

        if(passwordResetToken.isUsed())
            throw new RuntimeException("Password reset token is already used");

        if(passwordResetToken.getExpiresDate().isBefore(Instant.now()))
        throw new RuntimeException("Password reset token has Expired");

        User user=passwordResetToken.getUser();
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);

        passwordResetToken.setUsed(true);
        passwordResetTokenRepo.save(passwordResetToken);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        Optional<User> user=userRepository.findByEmail(email);
        return user;
    }

    @Override
    public User registerUser(User newUser) {
if(newUser.getPassword() !=null)
    newUser.setPassword(passwordEncoder.encode(newUser.getPassword()));
    return userRepository.save(newUser);

    }

    @Override
    public GoogleAuthenticatorKey generate2FASecret(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        GoogleAuthenticatorKey key=totpService.generateSecret();
        user.setTwoFactorSecret(key.getKey());
        userRepository.save(user);
        return key;
    }

    @Override
    public boolean validate2FACode(Long userId, int code) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        return totpService.verifyQRCodeUrl(user.getTwoFactorSecret(), code);
    }

    @Override
    public void enable2FA(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    @Override
    public void disable2FA(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
        user.setTwoFactorEnabled(false);
        userRepository.save(user);
    }

    @Override
    public void updateCredentials(Long userId, String newUsername, String newPassword) {
        User user = userRepository.findById(userId).
                orElseThrow(() -> new RuntimeException("User not found"));

        user.setUserName(newUsername);
        if(newPassword!=null) {
            user.setPassword(passwordEncoder.encode(newPassword));
        }
        userRepository.save(user);
    }

    @Override
    public void updateExpiryStatus(Long userId, boolean checked) {
        User user = userRepository.findById(userId).
                orElseThrow(() -> new RuntimeException("User not found"));

        user.setAccountNonExpired(!checked);
        userRepository.save(user);
    }

}
