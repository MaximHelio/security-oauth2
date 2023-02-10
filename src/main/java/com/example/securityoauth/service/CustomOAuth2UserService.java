package com.example.securityoauth.service;

import com.example.securityoauth.domain.CustomUser;
import com.example.securityoauth.domain.OAuthAttributes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.parameters.P;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("loadUser..");
        OAuth2UserService delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                                                    .getUserInfoEndpoint().getUserNameAttributeName();
        log.info("loaderUser registrationId = " + registrationId);
        log.info("loadUser userNameAttributeName = " + userNameAttributeName);

        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        log.info("attributes - " + attributes.getAttributes());

        String nameAttributeKey = attributes.getNameAttributeKey();
        String name = attributes.getName();
        String email = attributes.getEmail();
        String picture = attributes.getPicture();
        String id = attributes.getId();
        String socailType = "";

        if("naver".equals(registrationId)) {
            socailType = "naver";
        }else if("kakao".equals(registrationId)) {
            socailType = "kakao";
        }else{
            socailType = "google";
        }
        log.info("loadUser - nameAttributeKey = " + nameAttributeKey);
        log.info("loaduser - id = " + id);
        log.info("loaduser - socialType = " + socailType);
        log.info("loaduser - name = " + name);
        log.info("loaduser - email = " + email);
        log.info("loaduser - picture = " + picture);

        if(name == null) name = "";
        if(email == null) email = "";

        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
        authorities.add(authority);

        return new CustomUser(name, authorities, attributes);
    }



}
