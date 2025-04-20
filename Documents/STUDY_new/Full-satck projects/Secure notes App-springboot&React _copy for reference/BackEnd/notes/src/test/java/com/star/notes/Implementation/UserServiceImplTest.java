package com.star.notes.Implementation;

import com.star.notes.Model.User;
import com.star.notes.Repository.UserRepo;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {

    @Mock
    UserRepo userRepo;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    TotpServiceImpl totpService;
    @InjectMocks
    UserServiceImpl userService;

    @BeforeAll
    static void initAll() {
        System.out.println("Before All Tests");
    }

    @BeforeEach
    void init() {
        System.out.println("Before Each Test");
    }

    @AfterEach
    void tearDown() {
        System.out.println("After Each Test");
    }
    @AfterAll
    static void tearDownAll() {
        System.out.println("After All Tests");
    }

    @Test
    void myFirstTest() {
        System.out.println("myFirstTest");
        User user = new User();
        user.setUserName("test");
        user.setPassword("test");
        user.setEmail("test@test.com");
        Mockito.when(userRepo.save(user)).thenReturn(user);

       User user1= userService.registerUser(user);


       Assertions.assertEquals(user.getUserId(),user1.getUserId());
    }

    @Test
    void testDisable2FA() {
        // Arrange
        System.out.println("mySecondTest");
        Long userId = 1L;
        User mockUser = new User();
        mockUser.setUserId(userId);
        mockUser.setTwoFactorEnabled(true);

        //First check whether user is getting from database
        when(userRepo.findById(userId)).thenReturn(Optional.of(mockUser));

        // Act
        //then calling the method
        userService.disable2FA(userId);

        // Assert
        // Check if twoFactorEnabled was set to false
        //After calling values is set to false
        assert(!mockUser.isTwoFactorEnabled());

        // Verify save() was called with updated user
        //checking whether save(mockUser) called once
        verify(userRepo, times(2)).save(mockUser);
    }

    @Test
     void validate2FACodeTest() {
        User user = new User();
        user.setUserId(1L);
        user.setUserName("test1");
        user.setPassword("test1");
        user.setEmail("test1@test.com");
        user.setTwoFactorSecret("SECRET123");
        int code =12345;
        when(userRepo.findById(1L)).thenReturn(Optional.of(user));
        when(totpService.verifyQRCodeUrl("SECRET123", code)).thenReturn(true);

        // Act
        boolean result = userService.validate2FACode(1L, code);

        // Assert
        assertTrue(result);
        verify(totpService, times(1)).verifyQRCodeUrl("SECRET123", code);
    }

}