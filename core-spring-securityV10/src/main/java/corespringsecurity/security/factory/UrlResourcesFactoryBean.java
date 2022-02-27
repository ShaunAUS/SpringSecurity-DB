package corespringsecurity.security.factory;

import corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

//DB에서 가져온 자원URL,권한정보를 map형태로   -> MetadataSource 의 Reuqest 객체에게 전달하는 역활
public class UrlResourcesFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {



    //DB에서 가져온 정보를 map형태로 만들어주는 service
    private SecurityResourceService securityResouceService;
    //DB에서 가져온 자원정보,권한정보
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;


    public void setSecurityResouceService(SecurityResourceService securityResouceService) {
        this.securityResouceService = securityResouceService;
    }


    // securityResouceService 가 DB에서 가져온 데이터를 map으로 만들어서 가져온다
    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

        if(resourceMap == null){
            init();
        }
        return resourceMap;
    }


    //DB에서 가져온 정보를 map형태로 만들어주는 service  -> resourceMap에 넣기
    private void init() {
        resourceMap = securityResouceService.getResourceList();
    }


    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    //싱글톤  == 메모리에 단 하나만 존재하도록 함
    @Override
    public boolean isSingleton() {
        return true;
    }
}
