package corespringsecurity.security.filter;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

//인가 처리가 필요없는 부분들은 interceptor에 가기전에 처리하기위한 클래스
public class PermitAllFilter extends FilterSecurityInterceptor {

    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;


    //인증이나 권한 검사가 필요없은 자원들 저장공간
    private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();

    
    public PermitAllFilter(String...permitAllResources){

        for (String resource : permitAllResources) {
            permitAllRequestMatcher.add(new AntPathRequestMatcher(resource));
            
        }
    }


    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {


        boolean permitAll = false;

        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for(RequestMatcher requestMatcher : permitAllRequestMatcher){

            if(requestMatcher.matches(request)){
                permitAll =true;
                break;
            }

        }

        if(permitAll){

            //null -> 권한심사 x
            return null;
        }

        //만약에 위에 과정을 다통과하면(인가처리가 필요한데이터이면) 밑에 부모클래스를 호출해 인가 처리 시작
        //그전에는 사전차단
        return super.beforeInvocation(object);
    }



    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        if (this.isApplied(filterInvocation) && this.observeOncePerRequest) {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        } else {
            if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
                filterInvocation.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
            }

            //부모 클래스 지우기(super)
            InterceptorStatusToken token = beforeInvocation(filterInvocation);

            try {
                filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            } finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, (Object)null);
        }
    }

    private boolean isApplied(FilterInvocation filterInvocation) {
        return filterInvocation.getRequest() != null && filterInvocation.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null;
    }
}
