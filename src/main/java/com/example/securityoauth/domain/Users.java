package com.example.securityoauth.domain;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class Users {

    private int userNo;
    private String userId;
    private String userPw;
    private String userPwChk;
    private String name;
    private String email;
    private int enabled;
    private LocalDateTime regDate;
    private LocalDateTime updDate;

}