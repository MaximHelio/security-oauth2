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
    // 로그인 페이지
    @GetMapping("/auth/login")
    public String login(String code, HttpServletRequest request) throws Exception {

        log.info("code : " + code);

        // 인가코드 받아왔으면, 인증토큰 요청
        if( code != null ) {

            // rest 방식으로 요청을 보내는 템플릿
            RestTemplate rt = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");


            // 요청 body에 들어갈 요청파라미터를 관리하는 객체
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            // params.add("요청 파라미터명", "값");
            params.add("grant_type", grantType);
            params.add("client_id", clientId);
            params.add("redirect_uri", redirectUri);
            params.add("code", code);						// 인가코드
            params.add("client_secret", clientSecret);

			/*
			 {
			 	'grant_type' 		: ?????,
			 	'client_id"' 		: ?????,
			 	'redirect_uri' 		: ?????,
			 	'code' 				: ?????,
			 	'client_secret' 	: ?????,
			  }
			*/

            // 헤더, 바디 HttpEntity 객체에 포함
            HttpEntity<MultiValueMap<String, String>> tokenRequest = new HttpEntity<>(params, headers);



            // 요청
            String requestURL = "https://kauth.kakao.com/oauth/token";
            ResponseEntity<String> response =  rt.exchange(requestURL, HttpMethod.POST, tokenRequest, String.class);

            HttpStatus status = response.getStatusCode();
            log.info("response : " + response);


            // 인증토큰 발급되었으면,
            if( status == HttpStatus.OK ) {
                String body = response.getBody();
                log.info("body : " + body);

                // 액세스 토큰
                // JSON to Java Object (body --> KakaoToken)
                ObjectMapper objectMapper = new ObjectMapper();
                KakaoToken kakaoToken = objectMapper.readValue(body, KakaoToken.class);
                String accessToken = kakaoToken.getAccess_token();

                log.info("accessToken : " + accessToken );

                // 사용자 정보 가져오기
                HttpHeaders userInfoHeader = new HttpHeaders();

                String authorization = "Bearer " + accessToken;



                userInfoHeader.add("Authorization", authorization);
                userInfoHeader.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");

                HttpEntity<HttpHeaders> userInfoRequest = new HttpEntity<>(userInfoHeader);
                String userInfoURL = "https://kapi.kakao.com/v2/user/me";
                ResponseEntity<String> userInfoResponse = rt.exchange(userInfoURL, HttpMethod.POST, userInfoRequest, String.class);
                log.info("userInfoResponse : " + userInfoResponse);
                String userInfo = userInfoResponse.getBody();
                log.info("userInfo : " + userInfo);

//                KakaoUserInfo kakaoUserInfo = objectMapper.readValue(userInfo, KakaoUserInfo.class);
//                log.info("kakaoUserInfo :  " + kakaoUserInfo);
//
//
//                // 가입된 사용자인지 확인
//                // - X -> 회원가입
//                // 		- ID : "kakao-email" 형식으로
//                // 		- PW : "kakao-UID(0,8)"
//
//                KakaoAccount kakaoAccount = kakaoUserInfo.getKakao_account();
//                log.info( kakaoAccount.getEmail() );
//                String email = kakaoAccount.getEmail();
//                String nickname = kakaoAccount.getProfile().getNickname();
//
//                String userId = "kakao-" + email;
//                UUID uid = UUID.randomUUID();
//                String userPw = "kakao-" + uid.toString().substring(0,8);
//
//                Users user = new Users();
//                user.setEmail(email);
//                user.setUserId(userId);
//                user.setUserPw(userPw);
//                user.setName(nickname);
//                user.setUserPwChk(userPw);
//
//                Users joinedUser = userService.selectByUserId(user);
//                log.info("joinedUser : " + joinedUser);
//                if( joinedUser == null ) {
//                    userService.join(user);
//                    log.info("회원가입됨...");
//                }
//                log.info("userId : " + userId);
//                log.info("userPw : " + userPw);
//
//                boolean authenticated = false;
//                // - O -> 로그인
//                if( joinedUser != null ) {
//                    log.info("로그인 시도...");
//                    authenticated = userService.tokenAuthention(joinedUser, request);
//                }
//                log.info("authenticated : " + authenticated);

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
