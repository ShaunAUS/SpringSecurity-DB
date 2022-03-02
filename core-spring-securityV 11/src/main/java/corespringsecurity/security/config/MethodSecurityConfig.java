package corespringsecurity.security.config;



import corespringsecurity.enums.SecurtiyMethodType;
import corespringsecurity.security.factory.MethodResourcesFactoryBean;
import corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;

//Map 기반 메서드 보안처리
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true) //
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {


    @Autowired
    private SecurityResourceService securityResourceService;

    //GlobalMethodSeucurityConfiguration은 초기화시 이 메서드를 실행 시킨다.
    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {

        //map기반 인가처리 하는 객체
        //두개의 생성자가 있다. 하나는 기본, 하나는 map으로 권한처리하는 생성자
        return mapBasedMethodSecurityMetadataSource();
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {

        //DB에서 권한정보를 map으로 가져와서 생성자에게 보내준다.(map으로 권한정보 던져주면 알아서 파싱하고 해당 메서드들 빈 찾아서 프록시 생성)
        //우리는 문자열을 던졌지만 안에서 알아서 키와 벨류로 알아서 파씽해준다
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());

    }


    //DB에서 권한정보가져와 map에 저장 (메서드 방식)(MapBased)
    @Bean
    public MethodResourcesFactoryBean methodResourcesMapFactoryBean() {

        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResouceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("method");

        return methodResourcesFactoryBean;
    }

    //포인트컷 방식
    @Bean
    public MethodResourcesFactoryBean pointResourcesMapFactoryBean() {

        MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
        methodResourcesFactoryBean.setSecurityResouceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("pointcut");

        return methodResourcesFactoryBean;
    }




    @Bean
    public ProtectPointcutPostProcessor ProtectPointcutPostProcessor(){

        //포인트컷에서 만든 권한정보를 mapBased에 넘겨줘야하니까
        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        //DB에서 만든 resourceMap 전달
        protectPointcutPostProcessor.setPointcutMap(pointResourcesMapFactoryBean().getObject());

        return protectPointcutPostProcessor;
    }



    //pointcut는 public이 아니기 때문에 리플렉션 방식으로 bean 등록해줘야함
    //우리가 가져온 DB권한정보 map 을 protectPointcutPostProcessor에게 전달
    @Bean
    @Profile("pointcut")
    BeanPostProcessor protectPointcutPostProcessor2() throws Exception {

        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
        declaredConstructor.setAccessible(true);
        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
        setPointcutMap.setAccessible(true);
        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());

        return (BeanPostProcessor)instance;
    }

    @Bean
    @Profile("pointcut")
    public MethodResourcesFactoryBean pointcutResourcesMapFactoryBean(){

        MethodResourcesFactoryBean pointcutResourcesMapFactoryBean = new MethodResourcesFactoryBean();
        pointcutResourcesMapFactoryBean.setSecurityResouceService(securityResourceService);
        pointcutResourcesMapFactoryBean.setResourceType(SecurtiyMethodType.POINTCUT.getValue());
        return pointcutResourcesMapFactoryBean;
    }
}
