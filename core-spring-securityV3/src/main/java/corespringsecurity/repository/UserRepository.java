package corespringsecurity.repository;

import corespringsecurity.domain.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account,Long> {
    Account findByUserName(String username);
}
