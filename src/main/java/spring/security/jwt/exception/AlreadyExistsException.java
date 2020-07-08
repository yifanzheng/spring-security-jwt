package spring.security.jwt.exception;

import org.zalando.problem.AbstractThrowableProblem;
import org.zalando.problem.Status;
import spring.security.jwt.constant.ErrorConstants;

/**
 * AlreadyExistsException
 *
 * @author star
 */
public class AlreadyExistsException extends AbstractThrowableProblem {

    private static final long serialVersionUID = 4775907845387588528L;

    public AlreadyExistsException(String message) {
        super(ErrorConstants.DEFAULT_TYPE, message, Status.CONFLICT);
    }
}
