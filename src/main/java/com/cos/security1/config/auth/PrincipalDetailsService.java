package com.cos.security1.config.auth;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//시큐리티 설정에서 loginProcessingUrl("/login");
//login 요청이 오면 자동으로 IoC컨테이너에서 UserDetailsService으로 등록되어 있는 타입을 찾음. 후에 loadUserByUsername 함수를 호출
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // 시큐리티 session에는 Authentication 타입만이 들어갈 수 있고, 해당 타입은 UserDetails 타입만 담을 수 있다. 중요!
    // 해당 함수가 호출되면 UserDetails 타입으로 returnㅇ 되는데 자동 생성된 Authentication 타입에 들어가는 것
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        if(userEntity != null) {
            return new PrincipalDetails(userEntity);
        }
        return null;
    }

}
