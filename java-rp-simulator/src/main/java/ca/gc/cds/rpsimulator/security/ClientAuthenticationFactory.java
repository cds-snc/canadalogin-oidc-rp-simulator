package ca.gc.cds.rpsimulator.security;
 
import com.nimbusds.jose.jwk.JWK;

import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;

import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;

import org.springframework.stereotype.Component;
 
import java.nio.file.Files;

import java.nio.file.Paths;
 
@Component

public class ClientAuthenticationFactory {
 
    @Value("${CANADA_LOGIN_JWT_PRIVATE_KEY_PATH:private-key.pem}")

    private String privateKeyPath;
 
    public NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> createConverter() throws Exception {

        String pem = new String(Files.readAllBytes(Paths.get(privateKeyPath)));

        RSAKey rsaKey = new RSAKey.Builder((RSAKey) JWK.parseFromPEMEncodedObjects(pem))

                .keyID("javarp-2026")

                .build();
 
        return new NimbusJwtClientAuthenticationParametersConverter<>(registration -> {

            if ("canada-login-jwt".equals(registration.getRegistrationId())) {

                return rsaKey;

            }

            return null;

        });

    }

}

 