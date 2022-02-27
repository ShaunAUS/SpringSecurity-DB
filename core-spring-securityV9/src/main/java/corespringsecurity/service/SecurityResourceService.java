package corespringsecurity.service;

import corespringsecurity.domain.entity.Resources;
import corespringsecurity.repository.AccessIpRepository;
import corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

// DB에서 자원을 가져와 map형태로 가공 시켜주는 service
@Service
public class SecurityResourceService  {

    private ResourcesRepository resourceRepository;
    private AccessIpRepository accessIpRepository;

    public SecurityResourceService(ResourcesRepository resourceRepository, AccessIpRepository accessIpRepository) {
        this.resourceRepository =resourceRepository;
        this.accessIpRepository = accessIpRepository;
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

            });

            //key값(URL), 권한정보를 담아준다.
            result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributes);

        });

        return result;

    }

    //ip 주소 DB에서 가져오기
    public List<String> getAccessIpList() {

        //DB에서 가져와 map으로 List형태로 만들어주기
        // = IP List
        List<String> accessIpList = accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());


        return accessIpList;
    }


    //메서드 MAP방식
    public LinkedHashMap<String, List<ConfigAttribute>> getMethodResourceList() {

        //자원정보,권한정보 담을 그릇
        LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = resourceRepository.findAllMethodResources();
        resourcesList.forEach(re -> {
            List<ConfigAttribute> configAttributes = new ArrayList<>();
            re.getRoleSet().forEach(role -> {


                //권한 추출
                // Securityconfig 는 ConfigAttribute 인터페이스의 구현체
                //하나의 URL에 여러 권한이 있을수있다
                configAttributes.add(new SecurityConfig(role.getRoleName()));

            });
            //key값(URL), 권한정보를 담아준다.
            result.put(re.getResourceName(), configAttributes);

        });

        return result;

    }
}
