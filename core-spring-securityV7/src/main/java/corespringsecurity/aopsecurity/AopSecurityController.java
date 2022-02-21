package corespringsecurity.aopsecurity;

import corespringsecurity.domain.dto.AccountDTo;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AopSecurityController {


    // #을 붙이면 account에 참조가능
    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER')and #account.username ==principal.username")
    public String preAuthorize(AccountDTo account, Model model, Principal principal){

        model.addAttribute("method","Success @Preauthorize");

        return "aop/method";

    }
}
