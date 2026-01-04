import { Test, TestingModule } from '@nestjs/testing';
import { RolesService } from './roles.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Role } from '../../entities/role.entity';
import { Permission } from '../../entities/permission.entity';
import { Repository } from 'typeorm';
import { NotFoundException } from '@nestjs/common';

describe('RolesService', () => {
    let service: RolesService;
    let rolesRepository: Repository<Role>;
    let permissionsRepository: Repository<Permission>;

    const mockRole = {
        id: 'role-id',
        name: 'test-role',
        permissions: [
            { id: 'perm-1', slug: 'roles.create' },
            { id: 'perm-2', slug: 'roles.read' }
        ],
    } as Role;

    const mockPermissions = [
        { id: 'perm-3', slug: 'roles.update' },
        { id: 'perm-4', slug: 'roles.delete' },
    ] as Permission[];

    const mockRolesRepository = {
        findOne: jest.fn(),
        save: jest.fn(),
        create: jest.fn(),
        find: jest.fn(),
        remove: jest.fn(),
    };

    const mockPermissionsRepository = {
        findBy: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            providers: [
                RolesService,
                {
                    provide: getRepositoryToken(Role),
                    useValue: mockRolesRepository,
                },
                {
                    provide: getRepositoryToken(Permission),
                    useValue: mockPermissionsRepository,
                },
            ],
        }).compile();

        service = module.get<RolesService>(RolesService);
        rolesRepository = module.get<Repository<Role>>(getRepositoryToken(Role));
        permissionsRepository = module.get<Repository<Permission>>(getRepositoryToken(Permission));

        jest.clearAllMocks();
    });

    describe('setPermissions', () => {
        it('should replace existing permissions with new ones', async () => {
            mockRolesRepository.findOne.mockResolvedValue({ ...mockRole });
            mockPermissionsRepository.findBy.mockResolvedValue(mockPermissions);
            mockRolesRepository.save.mockImplementation((role) => Promise.resolve(role));

            const result = await service.setPermissions('role-id', { permissionIds: ['perm-3', 'perm-4'] });

            expect(mockRolesRepository.findOne).toHaveBeenCalledWith({ where: { id: 'role-id' }, relations: ['permissions'] });
            expect(mockPermissionsRepository.findBy).toHaveBeenCalled();
            expect(result.permissions).toHaveLength(2);
            expect(result.permissions).toEqual(mockPermissions);
        });

        it('should clear permissions if empty list is provided', async () => {
            mockRolesRepository.findOne.mockResolvedValue({ ...mockRole });
            mockRolesRepository.save.mockImplementation((role) => Promise.resolve(role));

            const result = await service.setPermissions('role-id', { permissionIds: [] });

            expect(mockPermissionsRepository.findBy).not.toHaveBeenCalled();
            expect(result.permissions).toHaveLength(0);
        });

        it('should throw NotFoundException if some permissions are missing', async () => {
            mockRolesRepository.findOne.mockResolvedValue({ ...mockRole });
            mockPermissionsRepository.findBy.mockResolvedValue([mockPermissions[0]]); // Return only 1 of 2 requested

            await expect(service.setPermissions('role-id', { permissionIds: ['perm-3', 'perm-4'] }))
                .rejects.toThrow(NotFoundException);
        });
    });
});
