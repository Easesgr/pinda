package com.itheima.pinda.zuul.filter;

import com.itheima.pinda.auth.client.properties.AuthClientProperties;
import com.itheima.pinda.auth.client.utils.JwtTokenClientUtils;
import com.itheima.pinda.auth.utils.JwtUserInfo;
import com.itheima.pinda.base.R;
import com.itheima.pinda.context.BaseContextConstants;
import com.itheima.pinda.exception.BizException;
import com.itheima.pinda.utils.StrHelper;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

/**
 * @author 安逸i
 * @version 1.0
 */
@Component
public class TokenContextFilter extends BaseFilter{

    @Autowired
    private AuthClientProperties authClientProperties;
    @Autowired
    private JwtTokenClientUtils jwtTokenClientUtils;

    @Override
    public String filterType() {
        return PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        /*
         一定要在
         org.springframework.cloud.netflix.zuul.filters.pre.PreDecorationFilter
         过滤器之后执行，因为这个过滤器做了路由,而我们需要这个路由信息来鉴权
         这个过滤器会将我们鉴权需要的信息放置在请求上下文中
         */

        return FilterConstants.PRE_DECORATION_FILTER_ORDER + 1;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    /**
     * 解析token信息放到请求头中
     * @return
     * @throws ZuulException
     */
    @Override
    public Object run() throws ZuulException {
        // 不进行拦截的地址
        if (isIgnoreToken()) {
            return null;
        }

        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();

        String userToken =
                request.getHeader(authClientProperties.getUser().getHeaderName());


        //2, 解析token
        JwtUserInfo userInfo = null;

        try {
            userInfo = jwtTokenClientUtils.getUserInfo(userToken);
        } catch (BizException e) {
            errorResponse(e.getMessage(), e.getCode(), 200);
            return null;
        } catch (Exception e) {
            errorResponse("解析token出错", R.FAIL_CODE, 200);
            return null;
        }

        //3, 将信息放入header
        if (userInfo != null) {
            addHeader(ctx, BaseContextConstants.JWT_KEY_ACCOUNT,
                    userInfo.getAccount());
            addHeader(ctx, BaseContextConstants.JWT_KEY_USER_ID,
                    userInfo.getUserId());
            addHeader(ctx, BaseContextConstants.JWT_KEY_NAME,
                    userInfo.getName());
            addHeader(ctx, BaseContextConstants.JWT_KEY_ORG_ID,
                    userInfo.getOrgId());
            addHeader(ctx, BaseContextConstants.JWT_KEY_STATION_ID,
                    userInfo.getStationId());
        }
        return null;
    }
    private void addHeader(RequestContext ctx, String name, Object value) {
        if (StringUtils.isEmpty(value)) {
            return;
        }
        ctx.addZuulRequestHeader(name, StrHelper.encode(value.toString()));
    }
}
