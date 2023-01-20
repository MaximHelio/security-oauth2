package com.example.securityoauth.security;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 로그인 성공처리 클래스
@Slf4j
public class CustomLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request
            , HttpServletResponse response
            , Authentication authentication) throws ServletException, IOException {

        log.info("인증 처리 성공...");
        // 아이디 저장 기능
        String rememberId = request.getParameter("remember-id");    // 아이디 저장 여부
        String username = request.getParameter("id");               // 아이디 저장

        log.info("rememberId: " + rememberId);
        log.info("username: " + username);

        // 아이디 저장 체크 -> 쿠키 생성
        if( rememberId != null && rememberId.equals("on") ){
            Cookie cookie = new Cookie("remember-id", username);
            cookie.setMaxAge(60*60*24);
//            cookie.setDomain();   // 도메인이 없어서, localhost에서는 테스트할 수 없음
            cookie.setPath("/");     // 루트로 해놓으면 하위의 모든 경로에서 요청시 쿠키를 다 날림
            response.addCookie(cookie);
        }// 아이디 저장 체크 x -> 쿠키 삭제
        else{
            Cookie cookie = new Cookie("remember-id", null);    // 값을 null
            cookie.setMaxAge(0);     // 유효기간 만료
//            cookie.setDomain();   // 도메인이 없어서, localhost에서는 테스트할 수 없음
            cookie.setPath("/");     // 루트로 해놓으면 하위의 모든 경로에서 요청시 쿠키를 다 날림
            response.addCookie(cookie);
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
