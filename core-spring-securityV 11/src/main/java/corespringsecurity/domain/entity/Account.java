package corespringsecurity.domain.entity;


import lombok.Builder;
import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Data
@Builder
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
