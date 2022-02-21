package corespringsecurity.service;

import corespringsecurity.domain.entity.Account;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    void createUser(Account account);
}
