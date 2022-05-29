package com.itheima.pinda.zuul.filter;

import cn.hutool.core.util.StrUtil;
import com.itheima.pinda.authority.dto.auth.ResourceQueryDTO;
import com.itheima.pinda.common.constant.CacheKey;
import com.itheima.pinda.context.BaseContextConstants;
import com.itheima.pinda.exception.code.ExceptionCode;
import com.itheima.pinda.zuul.api.ResourceApi;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import lombok.extern.slf4j.Slf4j;
import net.oschina.j2cache.CacheChannel;
import net.oschina.j2cache.CacheObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

/**
 * 权限验证过滤器
 * @author 安逸i
 * @version 1.0
 */
@Slf4j
@Component
public class AccessFilter extends BaseFilter{
    @Autowired
    private CacheChannel cacheChannel;
    @Autowired
    private ResourceApi resourceApi;



    @Override
    public String filterType() {
        return PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return FilterConstants.PRE_DECORATION_FILTER_ORDER + 10;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        //第1步：判断当前请求uri是否需要忽略
        if (isIgnoreToken()){
            // 直接放行
            return null;
        }
        //第2步：获取当前请求的请求方式和uri，拼接成GET/user/page这种形式，称为权限标识符
        RequestContext requestContext = RequestContext.getCurrentContext();
        HttpServletRequest request = requestContext.getRequest();
        String method = request.getMethod();
        String uri = request.getRequestURI();
        uri = StrUtil.subSuf(uri,zuulPrefix.length());
        uri = StrUtil.subSuf(uri, uri.indexOf("/",1));
        String permission = method + uri;
        //第3步：从缓存中获取所有需要进行鉴权的资源(同样是由资源表的method字段值+url字段值拼接成)，如果没有获取到则通过Feign调用权限服务获取并放入缓存中
        // 3.1 获取缓存中是否有
        CacheObject cacheObject = cacheChannel.get(CacheKey.RESOURCE, CacheKey.RESOURCE_NEED_TO_CHECK);
        List<String> resourceNeed2Auth = (List<String>) cacheObject.getValue();
        if (resourceNeed2Auth == null || resourceNeed2Auth.size() ==0){
            resourceNeed2Auth = resourceApi.list().getData();
            // 将数据缓存
            cacheChannel.set(CacheKey.RESOURCE, CacheKey.RESOURCE_NEED_TO_CHECK,resourceNeed2Auth);
            //第4步：判断这些资源是否包含当前请求的权限标识符，如果不包含当前请求的权限标识符，则返回未经授权错误提示
            long count = resourceNeed2Auth.stream().map(item->{
                return permission.startsWith(item);
            }).count();
            if (count == 0){
                errorResponse(ExceptionCode.UNAUTHORIZED.getMsg(),
                        ExceptionCode.UNAUTHORIZED.getCode(), 200);
                return null;
            }
        }
        //第5步：如果包含当前的权限标识符，则从zuul header中取出用户id，根据用户id取出缓存中的用户拥有的权限，如果没有取到则通过Feign调用权限服务获取并放入缓存，判断用户拥有的权限是否包含当前请求的权限标识符
        String userId = requestContext.getZuulRequestHeaders().
                get(BaseContextConstants.JWT_KEY_USER_ID);

        CacheObject cache = cacheChannel.get(CacheKey.USER_RESOURCE, userId);
        ResourceQueryDTO resourceQueryDTO = ResourceQueryDTO.builder().userId(new Long(userId)).build();
        // 缓存获取限权信息
        List<String> userResources = (List<String>) cacheChannel.get(CacheKey.USER_RESOURCE,userId).getValue();

        // 判断缓存中是否有该限权
        if (userResources == null || userResources.size() ==0){
            userResources = resourceApi.visible(resourceQueryDTO).getData().stream().map(item->{
                return item.getMethod() + item.getUrl();
            }).collect(Collectors.toList());
            // 判断是否有该权限

            cacheChannel.set(CacheKey.USER_RESOURCE,userId,userResources);
        }

        long count = userResources.stream().map(item -> {
            return permission.startsWith(item);
        }).count();

        if (count > 0){
            //第6步：如果用户拥有的权限包含当前请求的权限标识符则说明当前用户拥有权限，直接放行
            //有访问权限
            return null;
        }else {
            //第7步：如果用户拥有的权限不包含当前请求的权限标识符则说明当前用户没有权限，返回未经授权错误提示
            log.warn("用户{}没有访问{}资源的权限",userId,method + uri);
            errorResponse(ExceptionCode.UNAUTHORIZED.getMsg(),
                    ExceptionCode.UNAUTHORIZED.getCode(), 200);
        }
        return null;
    }
}
