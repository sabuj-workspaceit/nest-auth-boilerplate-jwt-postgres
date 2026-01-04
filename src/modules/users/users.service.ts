import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { User } from '../../entities/user.entity';
import { Role } from '../../entities/role.entity';
import { Permission } from '../../entities/permission.entity';
import { AssignRolesDto } from './dto/assign-roles.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersFilterDto } from './dto/users-filter.dto';
import { paginate } from '../../common/utils/pagination.util';
import { PaginatedResult } from '../../common/interfaces/paginated-result.interface';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private usersRepository: Repository<User>,
        @InjectRepository(Role)
        private rolesRepository: Repository<Role>,
    ) { }

    async findAll(filterDto: UsersFilterDto): Promise<PaginatedResult<User>> {
        const queryBuilder = this.usersRepository.createQueryBuilder('user')
            .leftJoinAndSelect('user.roles', 'roles');

        if (filterDto.isActive !== undefined) {
            queryBuilder.andWhere('user.isActive = :isActive', { isActive: filterDto.isActive });
        }

        if (filterDto.isEmailVerified !== undefined) {
            queryBuilder.andWhere('user.isEmailVerified = :isEmailVerified', { isEmailVerified: filterDto.isEmailVerified });
        }

        if (filterDto.role) {
            queryBuilder.andWhere('roles.name = :role', { role: filterDto.role });
        }

        return paginate(queryBuilder, filterDto, ['user.firstName', 'user.lastName', 'user.email']);
    }

    async findOne(id: string): Promise<User> {
        const user = await this.usersRepository.findOne({
            where: { id },
            relations: ['roles', 'roles.permissions'],
        });
        if (!user) {
            throw new NotFoundException('User not found');
        }
        return user;
    }

    async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
        const user = await this.findOne(id);
        Object.assign(user, updateUserDto);
        return this.usersRepository.save(user);
    }

    async remove(id: string): Promise<void> {
        const result = await this.usersRepository.delete(id);
        if (result.affected === 0) {
            throw new NotFoundException('User not found');
        }
    }

    async assignRoles(id: string, assignRolesDto: AssignRolesDto): Promise<User> {
        const user = await this.findOne(id);
        const { roleIds } = assignRolesDto;

        const roles = await this.rolesRepository.findBy({
            id: In(roleIds),
        });

        if (roles.length !== roleIds.length) {
            throw new NotFoundException('Some roles were not found');
        }

        user.roles = roles;
        return this.usersRepository.save(user);
    }

    async getRoles(id: string): Promise<Role[]> {
        const user = await this.findOne(id);
        return user.roles;
    }

    async getPermissions(id: string): Promise<Permission[]> {
        const user = await this.findOne(id);
        const rolePermissions = user.roles.flatMap(role => role.permissions);

        // Return unique permissions
        return [...new Map(rolePermissions.map(item => [item.id, item])).values()];
    }
}
