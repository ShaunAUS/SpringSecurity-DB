package corespringsecurity.security.voter;

import corespringsecurity.repository.AccessIpRepository;
import corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;

public class IpAddressVoter implements AccessDecisionVoter {

    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {

        this.securityResourceService = securityResourceService;
    }


    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class clazz) {
        return true;
    }

    //object에는 filterInvocation이 들어온다(클라가 가고자하는 자원정보)
    //이 자원에 필요한 권한정보 = collection ( FilterInovocationMetadataSource에서 가져온 권한정보)
    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {


        //사용자의 권한정보에서 사용자의 ip 정보 추출
        WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
        //ip가져오기
        String remoteAddress = details.getRemoteAddress();

        //DB에서 가져온 IP List
        List<String> accessIpList = securityResourceService.getAccessIpList();

        int result = ACCESS_DENIED;

        //사용자의 ip와 DB에 있는 ip정보 비교
        for (String ipAddress : accessIpList) {
            if(remoteAddress.equals(ipAddress)){

                //granted 하나만 나와도 통과
                return ACCESS_ABSTAIN;
            }

        }

        if(result == ACCESS_DENIED){

            throw new AccessDeniedException("Invalid IP Address");

        }

        return result;
    }


}
