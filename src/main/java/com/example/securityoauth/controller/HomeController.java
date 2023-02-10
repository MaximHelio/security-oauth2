package com.example.securityoauth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.parameters.P;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

@Slf4j
@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OAuth2User principal, Model model) throws Exception{

        if( principal != null) { // 인증자 사용자 정보가 들어있는 객체
            Map<String, Object> map = principal.getAttributes();
            log.info("map: " + map);
            log.info("map: " + map.get("properties"));

            Map<String, Object> proMap = (Map<String, Object>) map.get("properties");

            String profile_image = String.valueOf(proMap.get("profile_image"));
            String thumbnail_image = String.valueOf(proMap.get("thumbnail_image"));
            log.info("map: " + proMap);
            log.info("map: " + proMap.get("profile_image"));
            model.addAttribute("profile_image", profile_image);
            model.addAttribute("thumbnail_image", thumbnail_image);
        }
        return "index";
    }
}
