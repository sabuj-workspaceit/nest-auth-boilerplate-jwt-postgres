import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { REQUIRE_PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { User } from '../../../entities/user.entity';

@Injectable()
export class PermissionsGuard implements CanActivate {
    constructor(private reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        const requiredPermissions = this.reflector.getAllAndOverride<string[]>(REQUIRE_PERMISSIONS_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!requiredPermissions) {
            return true;
        }

        const { user } = context.switchToHttp().getRequest();

        if (!user) {
            throw new ForbiddenException('User not found in request');
        }

        const hasPermission = () => requiredPermissions.every((permission) =>
            this.checkPermission(user, permission),
        );

        if (!hasPermission()) {
            throw new ForbiddenException('Insufficient permissions');
        }

        return true;
    }

    private checkPermission(user: User, permissionSlug: string): boolean {
        if (!user.roles) return false;

        return user.roles.some((role) => {
            if (!role.permissions) return false;
            return role.permissions.some(p => p.slug === permissionSlug);
        });
    }
}
