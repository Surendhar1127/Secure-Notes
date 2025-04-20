package com.star.notes.Controller;

import com.star.notes.Model.AppRole;
import com.star.notes.Model.Role;
import com.star.notes.Model.User;
import com.star.notes.Repository.RoleRepo;
import com.star.notes.Repository.UserRepo;
import com.star.notes.Security.JWT.JwtUtils;
import com.star.notes.Security.Request.LoginRequest;
import com.star.notes.Security.Request.SignupRequest;
import com.star.notes.Security.Response.LoginResponse;
import com.star.notes.Security.Response.MessageResponse;
import com.star.notes.Security.Response.UserInfoResponse;
import com.star.notes.Security.Service.UserDetailsImpl;
import com.star.notes.Service.TotpService;
import com.star.notes.Service.UserService;
import com.star.notes.Util.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
AuthenticationManager authenticationManager;

    @Autowired
    private UserRepo userRepository;

    @Autowired
    private RoleRepo roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    private UserService userService;

    @Autowired
    AuthUtil authUtil;

    @Autowired
    TotpService totpService;

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            //By using user details giving authentication and will get authentication object
            System.out.println("valid user"+loginRequest.getUsername()+ " "+loginRequest.getPassword());
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            System.out.println("Invalid user");
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

//      set the authentication
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

       // String username = userDetails.getUsername();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Collect roles from the UserDetails
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Prepare the response body, now including the JWT token directly in the body
        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);

        // Return the response entity with the JWT token included in the response body
        return ResponseEntity.ok(response);
    }



    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        if (strRoles == null || strRoles.isEmpty()) {
            role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        } else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }


    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        System.out.println("User Details:"+userDetails);

        User user = userService.findByUsername(userDetails.getUsername());
System.out.println("User Details"+user);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        UserInfoResponse response = new UserInfoResponse(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        return ResponseEntity.ok().body(response);
    }


    @GetMapping("/username")
    public ResponseEntity<String> getUserName(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        if(username == null) {
            return ResponseEntity.ok("");
        }else {
            return ResponseEntity.ok(username);
        }
    }


    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        try{
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse("Password reset email has been sent"));
        }catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new MessageResponse("Error sending password reset email"));
        }
    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token,
                                           @RequestParam String newPassword) {
        try{
          userService.reserPassword(token,newPassword);
            return ResponseEntity.ok(new MessageResponse("Password reset successfully"));
        }catch (Exception e){
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    // 2FA Authentication
    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA() {
Long userId=authUtil.loggedInUserId();
        GoogleAuthenticatorKey secret =userService.generate2FASecret(userId);
        String qrCodeUrl=totpService.getQRCodeUrl(secret,userService.getUserById(userId).getUserName());
        return ResponseEntity.ok(qrCodeUrl);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA() {
        Long userId=authUtil.loggedInUserId();
        userService.disable2FA(userId);
        return ResponseEntity.ok("2FA disabled");
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code) {
        Long userId = authUtil.loggedInUserId();
        boolean isValid = userService.validate2FACode(userId, code);
        if (isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }

    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        User user = authUtil.loggedInUser();
        if (user != null){
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("User not found");
        }
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(@RequestParam int code,
                                                 @RequestParam String jwtToken) {
        String username = jwtUtils.getUserNameFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if (isValid) {
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }

@PostMapping("/update-credentials")
    public ResponseEntity<?> updateCredentials(@RequestParam String token,
                                               @RequestParam String newPassword,
                                               @RequestParam String newUsername) {

        System.out.println("Update token"+token);
    String username = jwtUtils.getUserNameFromJwtToken(token);
    User user = userService.findByUsername(username);
    try {
        userService.updateCredentials(user.getUserId(), newUsername, newPassword);

        return ResponseEntity.ok(new MessageResponse("Credentials updated successfully"));
    }catch (Exception e){
        e.printStackTrace();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }
}


@PutMapping("/update-expiry-status1")
    public ResponseEntity<?> updateExpiryStatus(@RequestParam String token,
                                                @RequestParam boolean checked) {
        System.out.println("update-expiry-status"+token);
    String username = jwtUtils.getUserNameFromJwtToken(token);
    User user = userService.findByUsername(username);
    try {
        userService.updateExpiryStatus(user.getUserId(),checked);

        return ResponseEntity.ok(new MessageResponse("Account Details updated successfully"));
    }catch (Exception e){
        e.printStackTrace();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
    }
}

}
