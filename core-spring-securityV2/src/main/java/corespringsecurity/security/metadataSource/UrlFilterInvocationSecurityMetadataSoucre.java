package corespringsecurity.security.metadataSource;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

//URL 방식 , 메서드 방식 둘다 SecurityMetadataSource 구현
//그래서 getAttributes 메서드의 매개변수는 Object형이다
public class UrlFilterInvocationSecurityMetadataSoucre implements FilterInvocationSecurityMetadataSource {


    //자원 요청정보와 , 그에따른 권한 정보 저장하는곳
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap =new LinkedHashMap<>();



    //Filter에서 이메서드를 호출할떄 파라미터 filterInvocation을 매개변수로 보낸다
    //URL 방식 , 메서드 방식 둘다 SecurityMetadataSource 구현
    //그래서 getAttributes 메서드의 매개변수는 Object형이다
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {


        //사용자가 요청한 자원정보
        HttpServletRequest request = ((FilterInvocation) object).getRequest();


        //그 요청한 자원이 있으면
        if(requestMap != null){

            //DB에서 가져온  자원url,권한정보 값
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
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
}
