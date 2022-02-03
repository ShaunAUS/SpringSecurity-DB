package corespringsecurity.security.provider;


import corespringsecurity.security.common.FormwebAuthenticationDetails;
import corespringsecurity.security.service.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;


//Provider

public class FormAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private  UserDetailsService userDetailsService;
    @Autowired
    private  PasswordEncoder passwordEncoder;

    public  FormAuthenticationProvider(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    //검증을 위한
    //AuthenticaitonManager 로부터 온 authentication 객체(username,password)
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {


        String userName = authentication.getName();
        String passWord = (String) authentication.getCredentials();


        //클라가 입력한 userName으로 계정이 있나없나 확인(userDetails타입으로 나온다)
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(userName);


        //사용자가 입력한 비밀번호 , DB에서 userName으로 가져온 계정 비밀번호 비교
        if(!passwordEncoder.matches(passWord,accountContext.getAccount().getPassWord())){

            throw new BadCredentialsException("Invalid Password");

        }

        String secretKey = ( (FormwebAuthenticationDetails) authentication.getDetails() ).getSecretKey();

        /*// 비밀번호 인증이 끝나고 난뒤 '추가정보' 에대한 인증 시작
        FormwebAuthenticationDetails details = (FormwebAuthenticationDetails) authentication.getDetails();
        String secretKey = details.getSecretKey();*/

        if(secretKey == null || ! secretKey.equals("secret")){

            throw new IllegalArgumentException("invalid Secret");

        }

        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        // 비밀번호까지 일치 했으면 인증성공 이므로 '인증결과 토큰' 을 생성한다
        /*UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                accountContext.getAccount(),
                null,
                accountContext.getAuthorities());

        return authenticationToken;
*/
    }


    //매개변수로 오는 authentication 의 타입과 CustomAuthenticationProvider 가 사용하는 토큰과 일치할때 이 provider 인증처리할수 있도록
    @Override
    public boolean supports(Class<?> authentication) {


        return authentication.equals(UsernamePasswordAuthenticationToken.class);
        //토큰이 매개변수 타입과 일치할때 이클래스가 인증을 처리하도록
        /*return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);*/
    }
}
