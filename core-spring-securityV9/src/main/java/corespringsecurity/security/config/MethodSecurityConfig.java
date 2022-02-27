package corespringsecurity.security.config;


import corespringsecurity.security.factory.MethodResourcesFactoryBean;
import corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

//Map 기반 메서드 보안처리
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true) //
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {


    @Autowired
    private SecurityResourceService securityResourceService;

    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {

        //map기반 인가처리 하는 객체
        //두개의 생성자가 있다. 하나는 기본, 하나는 map으로 권한처리하는 생성자
        return mapBasedMethodSecurityMetadataSource();
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {

        //DB에서 map으로 가져와서 생성자에게 보내준다.
        //우리는 문자열을 던졌지만 안에서 알아서 키와 벨류로 알아서 파씽해준다
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());

    }



    //DB에서 권한정보가져와 map에 저장 (메서드 방식)
    @Bean
    public MethodResourcesFactoryBean methodResourcesMapFactoryBean() {

        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResouceService(securityResourceService);

        return methodResourcesFactoryBean;
    }
}
