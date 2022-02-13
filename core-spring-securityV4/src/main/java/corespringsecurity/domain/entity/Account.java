package corespringsecurity.domain.entity;


import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Data
public class Account {

    @Id
    @GeneratedValue
    private Long id;
    private String userName;
    private String passWord;
    private String email;
    private String age;
    private String role;
}
