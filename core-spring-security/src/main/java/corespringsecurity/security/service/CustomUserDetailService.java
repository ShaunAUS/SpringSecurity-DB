package corespringsecurity.security.service;

import corespringsecurity.domain.dto.Account;
import corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


//user 찾은뒤 userDetails 타입으로 반환
//우리가 만든 '인증 처리' 스프링 시큐리티가 로그인시 이것을 사용
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private UserRepository userRepository;



    //인증 요청 ->AuthenticationManager -> AuthenticationProvider -> 적절한 provider선택 뒤 loadUserByUsername() 발동 -> userName으로 userDetailService 인터페이스에서 사용자가 있는지 없는지 확인
    // 확인뒤 userDetails 타입으로 반환
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {


        //userName 으로 계정찾기
        Account account = userRepository.findByUserName(username);

        //없으면 예외발생  // throws 처리
        if(account ==null){

            throw new UsernameNotFoundException("UserNameNotfound Exception");

        }

        //권한 설정
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));


        //AccountContext 는 user를 구현한 클래스
        //userDetails타입 +아이디+비번+권한 가져옴
        AccountContext accountContext = new AccountContext(account,roles);

        return accountContext;


    }
}
