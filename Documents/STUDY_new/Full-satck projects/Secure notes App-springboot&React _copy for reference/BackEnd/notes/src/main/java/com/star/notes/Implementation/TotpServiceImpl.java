package com.star.notes.Implementation;

import com.star.notes.Service.TotpService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;


@Service
public class TotpServiceImpl implements TotpService {

    private final GoogleAuthenticator gAuth;

    public TotpServiceImpl(GoogleAuthenticator gAuth) {
        this.gAuth = gAuth;
    }

    public TotpServiceImpl() {
        this.gAuth = new GoogleAuthenticator();
    }

    @Override
    public GoogleAuthenticatorKey generateSecret() {
        return gAuth.createCredentials();
    }

    @Override
    public String getQRCodeUrl(GoogleAuthenticatorKey secret, String username) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("Secure Notes Application",username,secret);
    }

    @Override
    public boolean verifyQRCodeUrl(String secret, int code) {
        return gAuth.authorize(secret,code);
    }
}
