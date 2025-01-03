package com.cos.security1.config;
import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록
@EnableGlobalMethodSecurity(securedEnabled = true) //secured 어노테이션 활성화, preAuthorize 활성화, postAuthorize 활성화
public class SecurityConfig {

    @Autowired
    private PrincipalOauth2UserService principalOauth2UserService;

    // Bean 어노테이션을 적으면 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다. 그럼 어디서든 쓸 수 있음.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user/**").authenticated() // /user라는 url로 들어오면 인증이 필요하다.
                        .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN") // manager으로 들어오는 MANAGER 인증 또는 ADMIN인증이 필요하다는 뜻이다.
                        .requestMatchers("/admin/**").hasRole("ADMIN") // //admin으로 들어오면 ADMIN권한이 있는 사람만 들어올 수 있음
                        .anyRequest().permitAll() //그리고 나머지 url은 전부 권한을 허용해준다.
                );

        http
                .formLogin(form -> form
                        .loginPage("/loginForm")
                        .loginProcessingUrl("/login")//login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 해줌
                        .defaultSuccessUrl("/")//로그인 성공시 기본 페이지
        )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/loginForm") // 구글 로그인이 완료된 뒤의 후처리가 필요함 Tip. 코드를 받는게 아니라, 엑세스토큰+사용자 프로필 정보를 한번에 받음
                        // 1.코드받기, 2.엑세스토큰(권한), 3. 사용자 프로필 정보를 가져오고, 4.1. 그 정보를 토대로 회원가입을 자동으로 진행시키기도 함, 4.2. 기본 정보(이메일,전화번호,이름,아이디)말고 추가적인 정보를 적게 하는 회원가입 창이 뜨기도 하는거임
                        .userInfoEndpoint(user -> user
                                .userService(principalOauth2UserService)));

        return http.build();
    }


}

