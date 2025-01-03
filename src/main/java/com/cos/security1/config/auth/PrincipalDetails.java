package com.cos.security1.config.auth;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 시큐리티 session을 만들어준다. (Security ContextHolder 이라는 키값에 세션 정보를 저장 시킴.)
//오브젝트 타입 -> Authentication 타입 객체
//Authentication 안에 User 정보가 있어야 됨.
//User 오브젝트 타입 -> UserDetail 타입 객체

//Security Session 영역안에 들어갈 수 있는 객체가 Authentication 객체이어야만 함.
// 그리고 이 객체 안에 들어가야 하는 유저 정보의 타입은 UserDetails이다.

import com.cos.security1.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

public class PrincipalDetails implements UserDetails, OAuth2User{

    private User user; //콤포지션
    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    //해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return user.getRole();
            }
        });
        return collect;
    }

    // password 리턴
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 1년동안 회원이 로그인을 안하면, 휴먼 계정으로 하기로함
        // 현재시간 - 로그인 시간 >= 1년을 초과하면 return false 등등...
        return true;
    }

    @Override
    public String getName() {
        return "";
    }
}
