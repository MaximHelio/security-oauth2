package com.example.securityoauth.utils;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class EncodeUtils {

    @Bean
    public static PasswordEncoder passWordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
