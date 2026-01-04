import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { hashPassword } from '../../utils/hash.util';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { User } from '../../entities/user.entity';
import { Role } from '../../entities/role.entity';
import { Permission } from '../../entities/permission.entity';
import { AssignRolesDto } from './dto/assign-roles.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersFilterDto } from './dto/users-filter.dto';
import { paginate } from '../../common/utils/pagination.util';
import { CreateUserDto } from './dto/create-user.dto';
import { PaginatedResult } from '../../common/interfaces/paginated-result.interface';
import { AssignRolesToUsersDto } from './dto/assign-roles-to-users.dto';

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

    async create(createUserDto: CreateUserDto): Promise<User> {
        const { email, password, roles: roleIds, ...otherDetails } = createUserDto;

        const existingUser = await this.usersRepository.findOne({ where: { email } });
        if (existingUser) {
            throw new ConflictException('User with this email already exists');
        }

        const hashedPassword = await hashPassword(password);

        let roles: Role[] = [];
        if (roleIds && roleIds.length > 0) {
            roles = await this.rolesRepository.findBy({
                id: In(roleIds),
            });

            if (roles.length !== roleIds.length) {
                throw new NotFoundException('Some roles were not found');
            }
        }

        const user = this.usersRepository.create({
            email,
            password: hashedPassword,
            ...otherDetails,
            roles,
        });

        return this.usersRepository.save(user);
    }

    async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
        const user = await this.findOne(id);
        const { roles: roleIds, email, password, ...otherUpdates } = updateUserDto;

        if (roleIds) {
            const roles = await this.rolesRepository.findBy({
                id: In(roleIds),
            });

            if (roles.length !== roleIds.length) {
                throw new NotFoundException('Some roles were not found');
            }
            user.roles = roles;
        }

        if (email && email !== user.email) {
            const existingUser = await this.usersRepository.findOne({ where: { email } });
            if (existingUser) {
                throw new ConflictException('User with this email already exists');
            }
            user.email = email;
            user.isEmailVerified = false;
        }

        if (password) {
            user.password = await hashPassword(password);
        }

        Object.assign(user, otherUpdates);
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

    async assignRolesToUsers(assignRolesToUsersDto: AssignRolesToUsersDto): Promise<User[]> {
        const { userIds, roleIds } = assignRolesToUsersDto;

        const users = await this.usersRepository.findBy({
            id: In(userIds),
        });

        if (users.length !== userIds.length) {
            throw new NotFoundException('Some users were not found');
        }

        const roles = await this.rolesRepository.findBy({
            id: In(roleIds),
        });

        if (roles.length !== roleIds.length) {
            throw new NotFoundException('Some roles were not found');
        }

        for (const user of users) {
            user.roles = roles;
        }

        return this.usersRepository.save(users);
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
