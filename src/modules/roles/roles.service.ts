import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, Repository } from 'typeorm';
import { Role } from '../../entities/role.entity';
import { Permission } from '../../entities/permission.entity';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';

@Injectable()
export class RolesService {
    constructor(
        @InjectRepository(Role)
        private rolesRepository: Repository<Role>,
        @InjectRepository(Permission)
        private permissionsRepository: Repository<Permission>,
    ) { }

    async create(createRoleDto: CreateRoleDto): Promise<Role> {
        const { permissionIds, ...rest } = createRoleDto;
        let permissions: Permission[] = [];

        if (permissionIds && permissionIds.length > 0) {
            permissions = await this.permissionsRepository.findBy({
                id: In(permissionIds),
            });
            if (permissions.length !== permissionIds.length) {
                throw new NotFoundException('Some permissions were not found');
            }
        }

        const role = this.rolesRepository.create({
            ...rest,
            permissions,
        });
        return this.rolesRepository.save(role);
    }

    findAll(): Promise<Role[]> {
        return this.rolesRepository.find({ relations: ['permissions'] });
    }

    async findOne(id: string): Promise<Role> {
        const role = await this.rolesRepository.findOne({
            where: { id },
            relations: ['permissions'],
        });
        if (!role) {
            throw new NotFoundException('Role not found');
        }
        return role;
    }

    async update(id: string, updateRoleDto: UpdateRoleDto): Promise<Role> {
        const role = await this.findOne(id);
        const { permissionIds, ...rest } = updateRoleDto as any;

        if (permissionIds) {
            const permissions = await this.permissionsRepository.findBy({
                id: In(permissionIds),
            });
            if (permissions.length !== permissionIds.length) {
                throw new NotFoundException('Some permissions were not found');
            }
            role.permissions = permissions;
        }

        Object.assign(role, rest);
        return this.rolesRepository.save(role);
    }

    async remove(id: string): Promise<void> {
        const role = await this.findOne(id);
        await this.rolesRepository.remove(role);
    }
}
