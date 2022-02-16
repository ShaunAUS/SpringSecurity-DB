package corespringsecurity.domain.dto;

import lombok.Data;

@Data
public class AccountDTo {
    private String userName;
    private String passWord;
    private String email;
    private String age;
    private String role;

}
