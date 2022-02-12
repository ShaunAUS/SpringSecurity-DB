package corespringsecurity.service.Impl;

import corespringsecurity.domain.entity.Account;
import corespringsecurity.repository.UserRepository;
import corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;


@RequiredArgsConstructor
public class  UserServiceImpl implements UserService {

    private final UserRepository userRepository;


    @Transactional
    @Override
    public void createUser(Account account) {

        userRepository.save(account);

    }
}
