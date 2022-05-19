package com.payau.demo2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user1").password(passwordEncoder().encode("user1")).roles()
                .and()
                .withUser("user2").password(passwordEncoder().encode("user2")).roles("CLIENT")
                .and()
                .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN", "CLIENT");
    }

    @Override
    protected void configure(final HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/authenticated").authenticated()
                .antMatchers("/client").hasRole("CLIENT")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest().permitAll()
                .and().logout().logoutSuccessUrl("/")
                .and().formLogin();
    }
}
