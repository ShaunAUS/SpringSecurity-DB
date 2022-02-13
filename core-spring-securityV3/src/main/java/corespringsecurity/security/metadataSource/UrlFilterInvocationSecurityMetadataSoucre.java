package corespringsecurity.security.metadataSource;

import corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

//URL 방식 , 메서드 방식 둘다 SecurityMetadataSource 구현
//그래서 getAttributes 메서드의 매개변수는 Object형이다
public class UrlFilterInvocationSecurityMetadataSoucre implements FilterInvocationSecurityMetadataSource {


    //DB에서 가져온 자원 요청정보와 , 그에따른 권한 정보 저장하는곳 =requestMap
    //LinkedHahsMap = 순서보장
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap ;

    private SecurityResourceService securityResourceService;



    //SecurityResourcesService 에서 map 형태로 데이터를-> RulResourcesFacotryBean -> MetadataSoruce  requestMap 에거 전달
    public UrlFilterInvocationSecurityMetadataSoucre(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourcesMap,SecurityResourceService securityResourceService) {
        this.requestMap = resourcesMap;
        this.securityResourceService = securityResourceService;
    }


    //FilterInterceptor -> FilterInvocation 생성 -> Default getAttribute호출 할떄 파라미터 filterInvocation을 매개변수로 보낸다
    //URL 방식 , 메서드 방식 둘다 SecurityMetadataSource 구현
    //그래서 getAttributes 메서드의 매개변수는 Object형이다
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {


        //사용자가 요청한 url자원정보
        HttpServletRequest request = ((FilterInvocation)object).getRequest();


        //그 요청한 자원이 있으면
        if(requestMap != null){

            //DB에서 가져온  자원url,권한정보 값
            //entrySet() = key-value쌍으로 Map.Entry타입의 객체를 저장한 Set
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){

                //key값 출력
                // 요청 url 정보
                RequestMatcher key = entry.getKey();

                // DB에서 가져온 자원URL과  클라가 요청한 자원URL이 같으면 value값(권한정보) 를 반환한다
                if(key.matches(request)){
                    return entry.getValue();
                }
            }

        }


        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    //인가처리 실시간 반영하기
    public void reload(){

        //다시 map데이터를 가져온다
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

        //기존 데이터 지워주고
        requestMap.clear();

        //다시 새로운 자원정보와,권한정보를 채워 넣어준다.
        while(iterator.hasNext()){

            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(),entry.getValue());
        }


    }
}
