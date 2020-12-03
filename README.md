## 前端方案：请求拦截

由于前端请求都是异步的，只有一个请求的时候，刷新 Token 是比较好处理的，但并发请求下刷新 Token 处理起来有点麻烦。我们需要考虑在多个请求几乎同时发起和且 Token 都时，当第一个请求进入 Token 刷新流程时，其他请求必须等待第一个请求完成 Token 刷新后再使用新 Token 进行重试。
简单地讲，就是同一时间有多个请求且 Token 都失效，在第一个请求进行 Token 刷新时，其他请求必须处于等待状态，直到 Token 刷新完成，才能携带新 Token 进行重试。

下面，我使用了 Angular 的请求拦截器，利用 BehaviorSubject 进行 Token 刷新状态的监听，当 Token 刷新成功，放行后面的请求进行重试。

除此之外，前端还可以利用 Promise，将请求存进队列中后，同时返回一个 Promise，让这个 Promise 一直处于 Pending 状态（即不调用 resolve），此时这个请求就会一直等啊等，只要我们不执行 resolve，这个请求就会一直在等待。当刷新 Token 的请求完成后 ，我们再调用 resolve，逐个重试。

**Angular 代码示列**

```ts
import { Injectable } from "@angular/core";
import {
  HttpEvent,
  HttpInterceptor,
  HttpHandler,
  HttpRequest,
  HttpErrorResponse
} from "@angular/common/http";
import { throwError, Observable, BehaviorSubject, of } from "rxjs";
import { catchError, filter, finalize, take, switchMap, mergeMap } from "rxjs/operators";

@Injectable()
export class AuthInterceptor implements HttpInterceptor {

  private refreshTokenInProgress = false;
  private refreshTokenSubject: BehaviorSubject<boolean> = new BehaviorSubject<boolean>(false);

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!req.headers.has("Content-Type")) {
      req = req.clone({
        headers: req.headers.set("Content-Type", "application/json")
      });
    }
    // 统一加上服务端前缀
    let url = req.url;
    if (!url.startsWith('https://') && !url.startsWith('http://')) {
      url = "./" + url;
    }
    req = req.clone({ url });
    req = this.setAuthenticationToken(req);

    return next.handle(req).pipe(
      mergeMap((event: any) => {
        // 若一切都正常，则后续操作
        return of(event);
      }),
      catchError((error: HttpErrorResponse) => {
        // 当是 401 错误时，表示 Token 已经过期，需要进行 Token 刷新
        if (error && error.status === 401) {
          if (this.refreshTokenInProgress) {
            // 如果 refreshTokenInProgress 为 true，我们将等到 refreshTokenSubject 是 true 时，才可以再次重试该请求
            // 这表示刷新 Token 动作已完成，新 Token 已准备就绪
            return this.refreshTokenSubject.pipe(
              filter(result => result),
              take(1),
              switchMap(() => next.handle(this.setAuthenticationToken(req)))
            );
          } else {
            this.refreshTokenInProgress = true;
            // 将 refreshTokenSubject 设置为 false，以便后面的请求调用时将处于等待状态，直到检索到新 Token 为止
            this.refreshTokenSubject.next(false);
            return this.refreshToken().pipe(
              switchMap((newToken: string) => {
                this.refreshTokenSubject.next(true);
                // 重新设置新的 Token
                localStorage.setItem("token", newToken);
                return next.handle(this.setAuthenticationToken(req));
              }),
              // 当刷新 Token 请求完成后，需要将 refreshTokenInProgress 设置为 false，用于下次刷新 Token
              finalize(() => (this.refreshTokenInProgress = false))
            );
          }
        } else {
          return throwError(error);
        }
      })
    );
  }

  private refreshToken(): Observable<any> {
    // 这里需要换成实际的 Token 刷新接口
    return of("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdGFyIiwicm9sZSI6WyJST0xFX1VTRVIiXSwiaXNzIjoic2VjdXJpdHkiLCJpYXQiOjE2MDY4MjczMDAsImF1ZCI6InNlY3VyaXR5LWFsbCIsImV4cCI6MTYwNjgzNDUwMH0.Hiq2DsH6j4XFd_v87lDWGlYembTLck7DjMLRLWdyvOo");
  }

  private setAuthenticationToken(request: HttpRequest<any>): HttpRequest<any> {
    return request.clone({
      headers: request.headers.set("Authorization", "Bearer " + localStorage.getItem("token"))
    });
  }
}
```
