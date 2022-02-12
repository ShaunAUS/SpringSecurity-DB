package corespringsecurity.security.config;


import corespringsecurity.security.common.FormAuthenticationDetailsSource;
import corespringsecurity.security.handler.CustomAccessDeniedHandler;
import corespringsecurity.security.metadataSource.UrlFilterInvocationSecurityMetadataSoucre;
import corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailService;
    private final FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;





    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {


        //provider는 우리가 만든 userDetailService 를 사용하기 때문에(안에 포함되기때문에) provider 선언
        auth.authenticationProvider(authenticationProvider());

        // 스프링 시큐리티가 우리가 만든 userDetailService 를 사용해서 '인증 처리'를 함
        //auth.userDetailsService(userDetailService);

    }

    //우리가 만든 provider 사용
    @Bean
    public AuthenticationProvider authenticationProvider() {

        return new FormAuthenticationProvider(passwordEncoder());
    }


    //패스워드 암호화
    @Bean
    public PasswordEncoder passwordEncoder() {

       return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //정적 파일들은 보안필터를 거치지 않는다.
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{

        http
                .authorizeRequests()
                .antMatchers("/","/users","user/login/**","login*").permitAll()
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/message").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")

                .anyRequest().authenticated()

        .and()

                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                .defaultSuccessUrl("/")
                //디테일까지 성공한뒤 ->인증 성공뒤 핸들러
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()


        .and()
                //이게 사용될때(인가예외발생시) exceptionTranslateFilter가 작동
                .exceptionHandling()
                .accessDeniedHandler(accessDenidedHandler())
        .and()

                //기존 filterInterCeptor 앞에 위치시키기
                .addFilterBefore(customFilterSecurityInterceptor(),FilterSecurityInterceptor.class)





                ;

    }

    @Bean
    private AccessDeniedHandler accessDenidedHandler() {

        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");

        return accessDeniedHandler;
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }




    // 커스텀 FilterSecurityInterceptor
    @Bean
    private FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {

        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();

        //인증정보
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        //권한 가져오기 // 메타데이타
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        //acceessDecisionManager
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());

        return filterSecurityInterceptor;

    }


    //accessDecisionManager 생성자에 List<Voter> 로 voter 여러개 전달 가능/ 여기서는 한개만
    @Bean
    private AccessDecisionManager affirmativeBased() {

        AffirmativeBased affirmativeBased =new AffirmativeBased(getAccessDecisionVoters());

        return affirmativeBased;
    }

    //여기서는 voter 한개만 list타입으로
    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        return Arrays.asList(new RoleVoter());
    }


    @Bean
    private FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {

        return new UrlFilterInvocationSecurityMetadataSoucre();
    }


}
