package com.star.notes.Service;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface TotpService {
    GoogleAuthenticatorKey generateSecret();

    String getQRCodeUrl(GoogleAuthenticatorKey secret, String username);

    boolean verifyQRCodeUrl(String secret, int code);
}
