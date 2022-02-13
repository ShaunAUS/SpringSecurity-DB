package corespringsecurity.service;

import corespringsecurity.domain.entity.Resources;
import corespringsecurity.repository.ResourceRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

// DB에서 자원을 가져와 map형태로 가공 시켜주는 service
@Service
public class SecurityResourceService  {

    private ResourceRepository resourceRepository;

    public SecurityResourceService(ResourceRepository resourceRepository) {
        this.resourceRepository =resourceRepository;

    }



    //DB로부터 자원가져와서 여기서 맵핑한다.
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        //자원정보,권한정보 담을 그릇
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = resourceRepository.findAllResources();
        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributes = new ArrayList<>();
            re.getRoleSet().forEach(role -> {


                //권한 추출
                // Securityconfig 는 ConfigAttribute 인터페이스의 구현체
                //하나의 URL에 여러 권한이 있을수있다
                configAttributes.add(new SecurityConfig(role.getRoleName()));
                //key값(URL), 권한정보를 담아준다.
                result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributes);

            });

        });

        return result;

    }
}
