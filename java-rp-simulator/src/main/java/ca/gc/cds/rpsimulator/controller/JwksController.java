package ca.gc.cds.rpsimulator.controller;
 
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
 
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Map;
 
@RestController
public class JwksController {
 
    @Value("${CANADA_LOGIN_JWT_CERT_PATH:certificate.pem}")
    private String certPath;
 
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (FileInputStream fis = new FileInputStream(certPath)) {
            cert = (X509Certificate) cf.generateCertificate(fis);
        }
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) cert.getPublicKey())
                .keyUse(KeyUse.SIGNATURE)   
                .keyID("javarp-2026")
                .x509CertChain(Collections.singletonList(Base64.encode(cert.getEncoded())))
                .x509CertThumbprint(Base64URL.encode(MessageDigest.getInstance("SHA-1").digest(cert.getEncoded())))
                .x509CertSHA256Thumbprint(Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())))
                .build();
        return new JWKSet(rsaKey).toJSONObject();
    }
}
 
 