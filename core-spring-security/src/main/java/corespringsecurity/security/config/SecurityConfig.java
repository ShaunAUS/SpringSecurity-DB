package corespringsecurity.security.config;


import corespringsecurity.security.common.FormAuthenticationDetailsSource;
import corespringsecurity.security.handler.CustomAccessDeniedHandler;
import corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailService;
    private final FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;


    //userDetailService 를 구현한게 user + 우리가 만든것(?)


    // 스프링 시큐리티가 우리가 만든 userDetailService 를 사용해서 '인증 처리'를 함
    // userDetailService 를 구현한 CustomUserDetailService(우리가 만든)를 실행!
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {



       // auth.userDetailsService(userDetailService);

        auth.authenticationProvider(authenticationProvider());
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




}
