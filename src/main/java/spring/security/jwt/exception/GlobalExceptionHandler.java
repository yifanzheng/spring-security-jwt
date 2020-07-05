package spring.security.jwt.exception;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.context.request.NativeWebRequest;
import org.zalando.problem.DefaultProblem;
import org.zalando.problem.Problem;
import org.zalando.problem.ProblemBuilder;
import org.zalando.problem.Status;
import org.zalando.problem.spring.web.advice.ProblemHandling;
import org.zalando.problem.spring.web.advice.validation.ConstraintViolationProblem;
import spring.security.jwt.constant.ErrorConstants;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 全局异常处理器
 *
 * <p>
 * 将服务器端异常处理为客户端友好的 JSON 格式。
 */
@ControllerAdvice
public class GlobalExceptionHandler implements ProblemHandling {

    @Override
    public ResponseEntity<Problem> process(@Nullable ResponseEntity<Problem> entity, NativeWebRequest request) {
        if (entity == null || entity.getBody() == null) {
            return entity;
        }
        Problem problem = entity.getBody();
        ProblemBuilder builder = Problem.builder()
                .withType(Problem.DEFAULT_TYPE.equals(problem.getType()) ? ErrorConstants.DEFAULT_TYPE : problem.getType())
                .withStatus(problem.getStatus())
                .withDetail(problem.getTitle())
                .with("path", request.getNativeRequest(HttpServletRequest.class).getRequestURI())
                .with("timestamp", new Date());

        if (problem instanceof ConstraintViolationProblem) {
            builder
                    .with("violations", ((ConstraintViolationProblem) problem).getViolations())
                    .with("message", ErrorConstants.ERR_VALIDATION);
        } else if (problem instanceof DefaultProblem) {
            builder
                    .withCause(((DefaultProblem) problem).getCause())
                    .withDetail(problem.getDetail())
                    .withInstance(problem.getInstance());
            problem.getParameters().forEach(builder::with);
            if (!problem.getParameters().containsKey("message") && problem.getStatus() != null) {
                builder.with("message", "error.http." + problem.getStatus().getStatusCode());
            }
        }

        return new ResponseEntity<>(builder.build(), entity.getHeaders(), entity.getStatusCode());
    }

    @Override
    public ResponseEntity<Problem> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, @Nonnull NativeWebRequest request) {
        BindingResult result = ex.getBindingResult();
        List<FieldError> fieldErrors = result.getFieldErrors().stream()
                .map(f -> new FieldError(f.getObjectName(), f.getField(), f.getCode()))
                .collect(Collectors.toList());

        Problem problem = Problem.builder()
                .withType(ErrorConstants.DEFAULT_TYPE)
                .withTitle("Method argument not valid")
                .withStatus(defaultConstraintViolationStatus())
                .with("message", ErrorConstants.ERR_VALIDATION)
                .with("fieldErrors", fieldErrors)
                .build();
        return create(ex, problem, request);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Problem> handleUsernameNotFoundException(UsernameNotFoundException ex, NativeWebRequest request) {
        Problem problem = Problem.builder()
                .withStatus(Status.NOT_FOUND)
                .with("message", ex.getMessage())
                .build();
        return create(ex, problem, request);
    }

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<Problem> handleServiceException(ServiceException ex, NativeWebRequest request) {
        Problem problem = Problem.builder()
                .withStatus(Status.INTERNAL_SERVER_ERROR)
                .withDetail(ex.getMessage())
                .build();
        return create(ex, problem, request);
    }

    @ExceptionHandler(HttpStatusCodeException.class)
    public ResponseEntity<?> restTemplateException(
            NativeWebRequest request, HttpStatusCodeException ex) {
        // 尝试获取原始异常信息，通常这只对本项目的其它组件有效
        String responseBody = ex.getResponseBodyAsString();
        return ResponseEntity
                .status(ex.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(responseBody);
    }
}