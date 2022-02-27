package corespringsecurity.security.init;

import corespringsecurity.service.Impl.RoleHierarchyServiceImpl;
import corespringsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

//DB에서 가져온 데이터들을 포맷팅 한뒤 -> RolehierachyImpl 에 넣어주는 작업
@Component
public class SecurityIntializer implements ApplicationRunner {


    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) throws Exception {

        //DB데이터가져와서 문자열로 포맷팅
        String allHierarchy = roleHierarchyService.findAllHierarchy();
        roleHierarchy.setHierarchy(allHierarchy);
    }
}
