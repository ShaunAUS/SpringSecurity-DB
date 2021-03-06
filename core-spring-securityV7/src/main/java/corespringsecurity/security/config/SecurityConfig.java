package corespringsecurity.security.config;


import corespringsecurity.security.common.FormAuthenticationDetailsSource;
import corespringsecurity.security.factory.UrlResourcesFactoryBean;
import corespringsecurity.security.filter.PermitAllFilter;
import corespringsecurity.security.handler.CustomAccessDeniedHandler;
import corespringsecurity.security.metadataSource.UrlFilterInvocationSecurityMetadataSoucre;
import corespringsecurity.security.provider.FormAuthenticationProvider;
import corespringsecurity.security.voter.IpAddressVoter;
import corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
@Order(0)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailService;
    private final FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;
    private final SecurityResourceService securityResourceService;


    private String[] permitAllResources ={"/","/login","/user/login/**" };




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
    private PermitAllFilter customFilterSecurityInterceptor() throws Exception {

        //????????? ???????????? ???????????? ??????
        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);

        //????????????
        permitAllFilter.setAuthenticationManager(authenticationManagerBean());
        //?????? ???????????? // ???????????????
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
        //acceessDecisionManager
        permitAllFilter.setAccessDecisionManager(affirmativeBased());

        return permitAllFilter;

    }


    //accessDecisionManager ???????????? List<Voter> ??? voter ????????? ?????? ??????/ ???????????? ?????????
    @Bean
    private AccessDecisionManager affirmativeBased() {

        AffirmativeBased affirmativeBased =new AffirmativeBased(getAccessDecisionVoters());

        return affirmativeBased;
    }

    //???????????? voter ????????? list????????????
    @Bean
    private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {

        List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();

        // ip voter??? ?????? ?????? ?????????
        // ???????????? ?????? voter??? granted ?????? ????????? ?????? ?????? ?????? ip??? ??????????????????
        accessDecisionVoters.add(new IpAddressVoter(securityResourceService));
        accessDecisionVoters.add(roleVoter());


        return accessDecisionVoters;
    }
    @Bean
    private AccessDecisionVoter<? extends Object> roleVoter() {

        //RoleHierarchyVoter ??? ????????? ???????????? roleHierachy??? ???????????? ??????
        RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierachy());

        return roleHierarchyVoter;
    }

    @Bean
    public RoleHierarchyImpl roleHierachy() {

        RoleHierarchyImpl roleHierarchyVoter =new RoleHierarchyImpl();
        return roleHierarchyVoter;

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
