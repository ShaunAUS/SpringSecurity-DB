package corespringsecurity.service.Impl;

import corespringsecurity.domain.entity.Account;
import corespringsecurity.repository.UserRepository;
import corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.transaction.annotation.Transactional;


@RequiredArgsConstructor
public class  UserServiceImpl implements UserService {

    private final UserRepository userRepository;


    @Transactional
    @Override
    public void createUser(Account account) {

        userRepository.save(account);

    }

    //order 메서드 시작전 권한검사(Advice) 한다
    @Override
    @Secured("ROLE_MANAGER")  //methodSecurityInterceptor 부분(Advice)
    public void order() {
        System.out.println("order");

    }
}
