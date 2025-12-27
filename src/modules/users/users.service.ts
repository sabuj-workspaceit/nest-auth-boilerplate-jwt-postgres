import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { User } from '../../entities/user.entity';
import { Role } from '../../entities/role.entity';
import { AssignRolesDto } from './dto/assign-roles.dto';

@Injectable()
export class UsersService {
    constructor(
        @InjectRepository(User)
        private usersRepository: Repository<User>,
        @InjectRepository(Role)
        private rolesRepository: Repository<Role>,
    ) { }

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
}
