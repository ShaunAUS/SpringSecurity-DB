package corespringsecurity.security.service;

import corespringsecurity.domain.entity.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


//userDetailService 인터페이스를 구현해놓은게 User클래스 ->이걸 상속받자!
public class AccountContext extends User {

    private final Account account;

    public Account getAccount() {
        return account;
    }

    //userName으 해당 계정+권한 가져오기 (userDetails타입으로 반환)
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUserName(), account.getPassWord() , authorities);
        this.account = account;



    }
}
