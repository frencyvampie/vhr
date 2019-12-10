package org.sang.config;

import org.sang.bean.Menu;
import org.sang.bean.Role;
import org.sang.service.MenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;
import java.util.List;

/**
 * Created by sang on 2017/12/28.
 * 该类的主要功能就是通过当前的请求地址，获取该地址需要的用户角色
 */
@Component
public class CustomMetadataSource implements FilterInvocationSecurityMetadataSource {
    @Autowired
    MenuService menuService;
    //这是来调用它match(String,String),将没一个数据库的menu的url和输入的url对比
    AntPathMatcher antPathMatcher = new AntPathMatcher();
    @Override
    //输入的url与所有的menu数据对比，如果匹配的上（antPathMatcher.match（））,就遍历对应的所有角色，并装进一个Collection<ConfigAttribute>返回，会进入AccessDecisionManager类
    public Collection<ConfigAttribute> getAttributes(Object o) {
    	//取出当前请求的url
        String requestUrl = ((FilterInvocation) o).getRequestUrl();
        //查询所有menu对象，目的是一个是url pattern，即匹配规则(比如/admin/**)，
        //还有一个是List,即这种规则的路径需要哪些角色才能访问
        List<Menu> allMenu = menuService.getAllMenu();
        for (Menu menu : allMenu) {
        	//当前请求url匹配上一个menu的url
            if (antPathMatcher.match(menu.getUrl(), requestUrl)
                    &&menu.getRoles().size()>0) {
            	//获取特定menu下的所有角色
                List<Role> roles = menu.getRoles();
                //遍历角色
                int size = roles.size();
                String[] values = new String[size];
                for (int i = 0; i < size; i++) {
                    values[i] = roles.get(i).getName();
                }
                return SecurityConfig.createList(values);
            }
        }
        //没有匹配上的资源，都是登录访问
        return SecurityConfig.createList("ROLE_LOGIN");
    }
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }
    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}
