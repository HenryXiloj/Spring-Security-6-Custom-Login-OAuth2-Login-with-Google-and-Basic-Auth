package com.henry.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeRequests( authorizeConfig -> {
                    authorizeConfig.requestMatchers("/").permitAll();
                    authorizeConfig.requestMatchers("/login/**").permitAll();
                    authorizeConfig.requestMatchers("/error").permitAll();
                    authorizeConfig.requestMatchers("/favicon.ico").permitAll();
                    authorizeConfig.anyRequest().authenticated();
                })
                .formLogin( login -> {
                    login.loginPage("/login").permitAll();
                    login.defaultSuccessUrl("/private");
                    login.failureUrl("/login?error=true").permitAll();
                }) //Custom Login
                .logout(logout -> {
                    logout.logoutSuccessUrl("/login?logout=true").permitAll();
                    logout.invalidateHttpSession(true).permitAll();
                    logout.deleteCookies("JSESSIONID").permitAll();
                })
                .httpBasic(Customizer.withDefaults()) // support basic auth
                .oauth2Login(oauth -> {
                    oauth.loginPage("/login").permitAll();
                    oauth.defaultSuccessUrl("/private");
                    oauth.failureUrl("/login?error=true").permitAll();
                }) // OpenID Connect with google
                 .addFilterBefore(new CustFilter(), UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(new AdminAuthenticateProvider())
                .csrf()
                .disable()
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("henry")
                        .password("{noop}password")
                        .authorities("ROLE_USER")
                        .build()
        );
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring() .requestMatchers("/resources/**", "/static/**", "/css/**");
    }
}
