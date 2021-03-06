package corespringsecurity.security.config;


import corespringsecurity.security.common.FormAuthenticationDetailsSource;
import corespringsecurity.security.factory.UrlResourcesFactoryBean;
import corespringsecurity.security.handler.CustomAccessDeniedHandler;
import corespringsecurity.security.metadataSource.UrlFilterInvocationSecurityMetadataSoucre;
import corespringsecurity.security.provider.FormAuthenticationProvider;
import corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.FactoryBean;
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
    private final SecurityResourceService securityResourceService;





    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {


        //provider??? ????????? ?????? userDetailService ??? ???????????? ?????????(?????? ?????????????????????) provider ??????
        auth.authenticationProvider(authenticationProvider());

        // ????????? ??????????????? ????????? ?????? userDetailService ??? ???????????? '?????? ??????'??? ???
        //auth.userDetailsService(userDetailService);

    }

    //????????? ?????? provider ??????
    @Bean
    public AuthenticationProvider authenticationProvider() {

        return new FormAuthenticationProvider(passwordEncoder());
    }


    //???????????? ?????????
    @Bean
    public PasswordEncoder passwordEncoder() {

       return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //?????? ???????????? ??????????????? ????????? ?????????.
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
                //??????????????? ???????????? ->?????? ????????? ?????????
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll()


        .and()
                //?????? ????????????(?????????????????????) exceptionTranslateFilter??? ??????
                .exceptionHandling()
                .accessDeniedHandler(accessDenidedHandler())
        .and()

                //?????? filterInterCeptor ?????? ???????????????
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




    // ????????? FilterSecurityInterceptor
    @Bean
    private FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {

        FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();

        //????????????
        filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
        //?????? ???????????? // ???????????????
        filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        //acceessDecisionManager
        filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());

        return filterSecurityInterceptor;

    }


    //accessDecisionManager ???????????? List<Voter> ??? voter ????????? ?????? ??????/ ???????????? ?????????
    @Bean
    private AccessDecisionManager affirmativeBased() {

        AffirmativeBased affirmativeBased =new AffirmativeBased(getAccessDecisionVoters());

        return affirmativeBased;
    }

    //???????????? voter ????????? list????????????
    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
        return Arrays.asList(new RoleVoter());
    }



    //BeanFactroy?????? ?????? map?????? ???????????? MetadataSource??? requestMap??? ??????
    @Bean
    private FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {

        return new UrlFilterInvocationSecurityMetadataSoucre(UrlResourcesFactoryBean().getObject(),securityResourceService);
    }



    private UrlResourcesFactoryBean UrlResourcesFactoryBean() {


        UrlResourcesFactoryBean urlResourcesFactoryBean = new UrlResourcesFactoryBean();

        // ??????????????? DB???????????? map?????? ?????? = SecurityResourceService
        urlResourcesFactoryBean.setSecurityResouceService(securityResourceService);

        return urlResourcesFactoryBean;

    }


}
