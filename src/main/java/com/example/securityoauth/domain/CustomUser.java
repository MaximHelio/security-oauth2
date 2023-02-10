package com.example.securityoauth.domain;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;

public class CustomUser extends DefaultOAuth2User {
    private static final long serialVersionUID = 1L;
    private String username;

    public CustomUser(String username, Collection<? extends GrantedAuthority> authorities, OAuthAttributes attributes) {
        super(authorities, attributes.getAttributes(), attributes.getNameAttributeKey());

        this.username = username;
    }
    public String getUsername() {
        return username;
    }
}
