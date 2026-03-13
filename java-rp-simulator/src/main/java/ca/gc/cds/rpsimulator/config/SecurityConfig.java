package ca.gc.cds.rpsimulator.config;
 
import org.springframework.context.annotation.Bean;

import org.springframework.context.annotation.Configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.web.SecurityFilterChain;
 
import static org.springframework.security.config.Customizer.withDefaults;
 
@Configuration

@EnableWebSecurity

public class SecurityConfig {
 
    @Bean

    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http

            .authorizeHttpRequests(authorize -> authorize

                .requestMatchers("/", "/error").permitAll() // Public pages

                .anyRequest().authenticated()              // Everything else needs login

            )

            .oauth2Login(withDefaults())  // Spring handles PKCE automatically

            .logout(logout -> logout

                .logoutSuccessUrl("/")

                .invalidateHttpSession(true)

                .clearAuthentication(true)

            );
 
        return http.build();

    }

}

 