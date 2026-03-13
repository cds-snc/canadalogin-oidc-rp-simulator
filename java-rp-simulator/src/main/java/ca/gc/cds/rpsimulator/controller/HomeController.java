package ca.gc.cds.rpsimulator.controller;
 
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
 
@RestController
public class HomeController {
 
    // Public landing page
    @GetMapping("/")
    public String home() {
        return "<h1>GC Sign-In Java RP Simulator</h1>" +
               "<p><a href='/oauth2/authorization/canada-login'>Log In with CanadaLogin</a></p>";
    }
 
    // Protected dashboard - only reachable after successful login
    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal OidcUser oidcUser) {
        return "<h1>Welcome, " + oidcUser.getFullName() + "!</h1>" +
               "<p><b>Email:</b> " + oidcUser.getEmail() + "</p>" +
               "<p><b>Subject (sub):</b> " + oidcUser.getSubject() + "</p>" +
               "<hr><h3>All Claims:</h3><pre>" + oidcUser.getClaims() + "</pre>" +
               "<br><a href='/logout'>Sign Out</a>";
    }
}