package corespringsecurity.aopsecurity;


import org.springframework.stereotype.Service;

@Service
public class AopPointCutService {

    public void pointSecured(){
        System.out.println("potincut secured");
    }

    public void notSecured(){
        System.out.println("not secured");
    }
}
