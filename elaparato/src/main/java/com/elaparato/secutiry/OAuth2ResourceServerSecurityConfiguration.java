package com.elaparato.secutiry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
@Configuration
public class OAuth2ResourceServerSecurityConfiguration {

    private final KeyCloakJwtAuthenticationConverter keyCloakJwtAuthenticationConverter;

    public OAuth2ResourceServerSecurityConfiguration(KeyCloakJwtAuthenticationConverter keyCloakJwtAuthenticationConverter) {
        this.keyCloakJwtAuthenticationConverter = keyCloakJwtAuthenticationConverter;
    }

    @Bean
    public SecurityFilterChain setupOAuth(HttpSecurity http) throws Exception {
        http.cors().and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .csrf().disable()
                .oauth2ResourceServer().jwt().jwtAuthenticationConverter(keyCloakJwtAuthenticationConverter).and().and()
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(new AntPathRequestMatcher("/productos/**")).hasAnyAuthority("ROLE_Repositor", "ROLE_Administrador")
                        .requestMatchers(new AntPathRequestMatcher("/ventas/**")).hasAnyAuthority("ROLE_Vendedor", "ROLE_Administrador")
                        .requestMatchers(new AntPathRequestMatcher("/users/**")).hasAnyAuthority( "ROLE_Administrador")
                        .anyRequest().authenticated()
                );
        return http.build();
    }


}
