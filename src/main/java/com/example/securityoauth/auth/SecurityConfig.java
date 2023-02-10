package com.example.securityoauth.auth;

import com.example.securityoauth.security.CustomLoginFailureHandler;
import com.example.securityoauth.security.CustomLoginSuccessHandler;
import com.example.securityoauth.service.CustomOAuth2UserService;
import com.example.securityoauth.utils.EncodeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;


import javax.sql.DataSource;

@Configuration          // 해당 클래스를 스프링 설정하는 빈으로 등록
@EnableWebSecurity      // 해당 클래스를 시큐리티 설정 클래스로 지정. 스프링 시큐리티 기능을 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 데이터 소스 객체 의존성 주입
    @Autowired
    private DataSource dataSource;

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests()
                .antMatchers("/").permitAll()                                 // 루트(/) 경로 요청에 대해 모두에게 허용
                .antMatchers("/auth/**").permitAll()
                .antMatchers("/css/**", "/js/**", "/img/**").permitAll()      // 정적 자원은 모두에게 허용
                // /admin 아래 요청에 대해 'ROLE_ADMIN' 권한에게 허용
                .anyRequest().authenticated();                                          // 그 외 다른 요청들은 허가된 경우에만 사용할 수 있도록

        // 폼 로그인 설정
        http.formLogin()
                .loginPage("/auth/login")           //로그인 페이지 URL 지정(default: /login)
                .loginProcessingUrl("/auth/login")  // 로그인 처리 URL 지정
                .usernameParameter("id")            // 로그인 폼 요청 ID 파라미터 지정(default: username)
                .passwordParameter("pw")            // 로그인 폼 요청 아이디 파라미터명 지정(default: password)
                .defaultSuccessUrl("/")             //로그인 성공시 기본 URL
                .successHandler(  authenticationSuccessHandler() )  // 로그인 성공처리 핸들러 지정
                .permitAll();                       // 로그인 URL 요청을 모두에게 허용

        // 폼 로그아웃 설정
        http.logout()                           // 로그아웃 URL 요청을 모두에게 허용
                .logoutUrl("/auth/logout")               // 로그아웃 처리 URL 지정 (default: "/logout")
                .logoutSuccessUrl("/")
                .permitAll();

        // 자동 로그인 security가 만든 Controller로 체크 여부 판단하고 있음
        // - 한번 로그인 하면, 브라우저 종료 후 다시 접속하여도 아이디/비밀번호 입력없이 자동으로 로그인하는 기능
        // - persistent_logins(자동 로그인 테이블)을 정의해야한다.
        // - remember-me라는 요청 파라미터를 포함하여 로그인 요청을 보내야 한다.
        http.rememberMe()                       // HttpSecurity 안에 rememberMe라는 메서드
                .key("aloha")                       // 암호화 혹은 복호화에 쓰이는 키
                // DataSource가 등록된 PersistentRepository 토큰저장 정보를 등록
                .tokenRepository( tokenRepository() )
                // 토큰 유효기간 설정 (초단위로)
                .tokenValiditySeconds(60 * 60 * 24);     // 1일

        // OAuth2 로그인 기능 활성화
        http.oauth2Login()
            .loginPage("/auth/login")
            .successHandler( authenticationSuccessHandler() )
            .failureHandler( authenticationFailureHandler() )
            .userInfoEndpoint()                         // OAuth2 로그인 성공 후 사용자 정보 설정
            .userService(customOAuth2UserService)       // 로그인 성공 후 처리할 서비스 설정
            ;
        ;

        // SSL 비활성화
        // http.csrf().disable();                  // 시큐리티가 CSRF 공격에 대한 보호 설정을 기본으로 해줌, 403에러 막음
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // JDBC 인증을 위해 필요한 정보
        // - 데이터 소스 (DB 정보 : 호스트URL, 아이디, 패스워드)
        // - 아이디/패스워드를 가져올 쿼리
        // - 권한을 가져올 쿼리
        // - 패스워드에 대한 암호화 방식

        String sql1 = " SELECT user_id AS username "
                + "       ,user_pw AS password "
                + "		  ,enabled "
                + " FROM users "
                + " WHERE user_id = ? "
                ;

        String sql2 = " SELECT user_id AS username "
                + "       , auth   AS authority "
                + " FROM user_auth "
                + " WHERE user_id = ? "
                ;

        auth.jdbcAuthentication()				// JDBC (DB)를 통한 인증방식으로 지정
                .dataSource(dataSource)				// 데이터 소스 지정
                .usersByUsernameQuery(sql1)			// 아이디/패스워드/사용가능여부 를 가져올 쿼리 지정
                .authoritiesByUsernameQuery(sql2)	// 권한을 가져올 쿼리 지정
                .passwordEncoder( EncodeUtils.passWordEncoder() )
        ;


    }
    // PersistentTokenRepository 객체 생성 메서드
    private PersistentTokenRepository tokenRepository(){
        JdbcTokenRepositoryImpl repositoryImpl = new JdbcTokenRepositoryImpl();
        repositoryImpl.setDataSource(dataSource);
        return repositoryImpl;
    }

    // 인증 성공 처리 클래스 - 빈 등록
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(){
        return new CustomLoginSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomLoginFailureHandler();
    }

    // 인증 관리자 클래스 - 빈 등록

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        //WebSecurityConfigurerAdapter 로부터 가져옴(override)
        return super.authenticationManagerBean();
    }

    // 스프링 시큐리티 설정 파일 내에서 빈 등록을 하면,
    // 순환참조가 일어나서 에러남 => 별도의 클래스에서 빈 등록을 해주어야 함.
    // 스프링 시큐리티 기본 암호화 방식
//    @Bean // 메서드에서 반환하는 객체를 스프링 컨테이너에 등록해줌 > 스프링 시작시, 해당 인스턴스가 필요한 시점에 컨테이너에서 꺼내옴
//    public BCryptPasswordEncoder passwordEncoder(){
//        return new BCryptPasswordEncoder();
//    }
}
