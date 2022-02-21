package corespringsecurity.config;


import corespringsecurity.repository.AccessIpRepository;
import corespringsecurity.repository.ResourcesRepository;
import corespringsecurity.service.SecurityResourceService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


//공통적으로쓰는 bean
@Configuration
public class AppConfig {

    //DB에서 가져와야하니 레파지토리 필요
    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourceRepository, AccessIpRepository accessIpRepository){

        SecurityResourceService securityResourceService = new SecurityResourceService(resourceRepository, accessIpRepository);

        return securityResourceService;

    }
}
