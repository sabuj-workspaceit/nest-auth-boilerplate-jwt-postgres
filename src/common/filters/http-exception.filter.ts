import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';
import { ApiResponse } from '../interfaces/api-response.interface';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
    catch(exception: unknown, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const status =
            exception instanceof HttpException
                ? exception.getStatus()
                : HttpStatus.INTERNAL_SERVER_ERROR;

        let message = 'Internal server error';
        let errors: any[] = [];

        if (exception instanceof HttpException) {
            const res = exception.getResponse();
            if (typeof res === 'string') {
                message = res;
            } else if (typeof res === 'object' && res !== null) {
                const errorResponse = res as any;
                message = errorResponse.message || message;
                if (Array.isArray(errorResponse.message)) {
                    errors = errorResponse.message;
                    message = 'Validation Failed'; // Common message if multiple errors
                } else {
                    // If it's not an array, maybe push specific error details if available
                    // For now, let's keep errors empty unless explicitly provided or standard validation array
                }
            }
        } else if (exception instanceof Error) {
            message = exception.message;
        }

        const apiResponse: ApiResponse<null> = {
            success: false,
            message,
            data: null,
            errors: errors.length > 0 ? errors : null,
        };

        response.status(status).json(apiResponse);
    }
}
