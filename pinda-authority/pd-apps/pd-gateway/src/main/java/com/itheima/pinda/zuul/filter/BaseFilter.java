package com.itheima.pinda.zuul.filter;

import cn.hutool.core.util.StrUtil;
import com.itheima.pinda.base.R;
import com.itheima.pinda.common.adapter.IgnoreTokenConfig;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletRequest;

/**
 * @author 安逸i
 * @version 1.0
 */
public abstract class BaseFilter extends ZuulFilter {

    // 获取网关前缀  /api
    @Value("${server.servlet.context-path}")
    protected String zuulPrefix;


    /**
     * 判断是否需要忽略过滤的网关
     * @return
     */
    protected boolean isIgnoreToken() {
        HttpServletRequest request =
                RequestContext.getCurrentContext().getRequest();
        String uri = request.getRequestURI();
        // 处理uri  /api/file/resource/list -> /resource/list
        uri = StrUtil.subSuf(uri, zuulPrefix.length());
        uri = StrUtil.subSuf(uri, uri.indexOf("/", 1));
        // 判断是否在忽略集合中
        return IgnoreTokenConfig.isIgnoreToken(uri);
    }

    /**
     * 认证失败返回报错
     * @param errMsg
     * @param errCode
     * @param httpStatusCode
     */
    protected void errorResponse(String errMsg, int errCode, int httpStatusCode) {
        R tokenError = R.fail(errCode, errMsg);
        RequestContext ctx = RequestContext.getCurrentContext();
        // 返回错误码
        ctx.setResponseStatusCode(httpStatusCode);
        ctx.addZuulResponseHeader(
                "Content-Type", "application/json;charset=UTF-8");
        if (ctx.getResponseBody() == null) {
            // 返回错误内容
            ctx.setResponseBody(tokenError.toString());
            // 过滤该请求，不对其进行路由
            ctx.setSendZuulResponse(false);
        }
    }

}
