package com.example.securityoauth.controller;

import com.example.securityoauth.domain.KakaoToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Controller
public class AuthController {

    @Value("${kakao.client-id}")
    private String clientId;

    @Value("${kakao.grant-type}")
    private String grantType;

    @Value("${kakao.redirect-uri}")
    private String redirectUri;

    @Value("${kakao.client-secret}")
    private String clientSecret;

    @Value("${kakao.admin-key]")
    private String adminKey;
    // 로그인 페이지
    @GetMapping("/auth/login")
    public String login(String code) throws Exception{

        log.info("code : " + code);

        // 인가 코드 받아왔으면, 인증토큰 요청
        if( code != null){

            // rest 방식으로 요청을 보내는 템플릿
            RestTemplate rt = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");

            log.info("");
            // 요청 body에 들어갈 spring security에 있는 여러 개의 요청 파라미터를 지정해주는 character(객체)
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            //params.add("요청 파라미터명", "값");
            params.add("grant_type", grantType);
            params.add("client_id", clientId);
            params.add("redirect_uri", redirectUri);
//            params.add("token", tokenRedirectUri);
            params.add("code", code);       //인가코드
            params.add("client_secret", clientSecret);
            /**
             * {
             *     'grant_type' : ????,
             *     'client_id' : ????,
             *     'redirect_uri' : ????,
             *     'code' : ????,
             *     'client_secret' : ????,
             * }
             */

            // 헤더, 바디 HttpEntity 객체에 포함
            HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(params, headers);

            // 요청
            String requestURL = "https://kauth.kakao.com/oauth/token";
            ResponseEntity<String> response = rt.exchange(requestURL, HttpMethod.POST, tokenRequest, String.class);

            HttpStatus status = response.getStatusCode();
            log.info("response: " + response);
            // 인증토큰 발급되었으면,
            if( status == HttpStatus.OK){
                String body = response.getBody();
                log.info("body: "+ body);

                // 액세스 토큰
                // JSON to Java Object( body --> kakaoToken)
                ObjectMapper objectMapper = new ObjectMapper();
                KakaoToken kakaoToken = objectMapper.readValue(body, KakaoToken.class);
                String accessToken = kakaoToken.getAccess_token();

                log.info("accessToken: " + accessToken);

                // 사용자 정보 가져오기
                HttpHeaders userInforHeader = new HttpHeaders();

                String authorization = "Bearer " + accessToken;

                userInforHeader.add("Authorization", authorization);
                userInforHeader.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");

                HttpEntity<HttpHeaders> userInfoRequest = new HttpEntity<>(userInforHeader);

                String userInfoURL = "https://kapi.kakao.com/v2/user/me";
                ResponseEntity<String> userInfoResponse = rt.exchange(userInfoURL, HttpMethod.POST, userInfoRequest, String.class);
                log.info("userInfoResponse: " + userInfoResponse);

            }

        }
        return "/auth/login";
    }
    // 인증 토큰 받기
    @GetMapping("/auth/login/kakao")
    public String loginKakao(){

        return "/auth/login/kakao";
    }


}
