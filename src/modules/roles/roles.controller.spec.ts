import { Test, TestingModule } from '@nestjs/testing';
import { RolesController } from './roles.controller';
import { RolesService } from './roles.service';
import { AddPermissionsDto } from './dto/add-permissions.dto';
import { CreateRoleDto } from './dto/create-role.dto';
import { UpdateRoleDto } from './dto/update-role.dto';

describe('RolesController', () => {
    let controller: RolesController;
    let service: RolesService;

    const mockRolesService = {
        create: jest.fn(),
        findAll: jest.fn(),
        findOne: jest.fn(),
        update: jest.fn(),
        remove: jest.fn(),
        addPermissions: jest.fn(),
    };

    beforeEach(async () => {
        const module: TestingModule = await Test.createTestingModule({
            controllers: [RolesController],
            providers: [
                {
                    provide: RolesService,
                    useValue: mockRolesService,
                },
            ],
        }).compile();

        controller = module.get<RolesController>(RolesController);
        service = module.get<RolesService>(RolesService);
    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });

    describe('create', () => {
        it('should create a role', async () => {
            const createRoleDto: CreateRoleDto = { name: 'admin', description: 'Admin role' };
            const expectedResult = { id: '1', ...createRoleDto, permissions: [] };
            mockRolesService.create.mockResolvedValue(expectedResult);

            expect(await controller.create(createRoleDto)).toEqual(expectedResult);
            expect(mockRolesService.create).toHaveBeenCalledWith(createRoleDto);
        });
    });

    describe('findAll', () => {
        it('should return an array of roles', async () => {
            const expectedResult = [{ id: '1', name: 'admin', description: 'Admin role', permissions: [] }];
            mockRolesService.findAll.mockResolvedValue(expectedResult);

            expect(await controller.findAll()).toEqual(expectedResult);
            expect(mockRolesService.findAll).toHaveBeenCalled();
        });
    });

    describe('findOne', () => {
        it('should return a single role', async () => {
            const id = '1';
            const expectedResult = { id, name: 'admin', description: 'Admin role', permissions: [] };
            mockRolesService.findOne.mockResolvedValue(expectedResult);

            expect(await controller.findOne(id)).toEqual(expectedResult);
            expect(mockRolesService.findOne).toHaveBeenCalledWith(id);
        });
    });

    describe('update', () => {
        it('should update a role', async () => {
            const id = '1';
            const updateRoleDto: UpdateRoleDto = { name: 'superadmin' };
            const expectedResult = { id, name: 'superadmin', description: 'Admin role', permissions: [] };
            mockRolesService.update.mockResolvedValue(expectedResult);

            expect(await controller.update(id, updateRoleDto)).toEqual(expectedResult);
            expect(mockRolesService.update).toHaveBeenCalledWith(id, updateRoleDto);
        });
    });

    describe('remove', () => {
        it('should remove a role', async () => {
            const id = '1';
            mockRolesService.remove.mockResolvedValue(undefined);

            expect(await controller.remove(id)).toBeUndefined();
            expect(mockRolesService.remove).toHaveBeenCalledWith(id);
        });
    });

    describe('addPermission', () => {
        it('should add permissions to a role', async () => {
            const id = '1';
            const addPermissionsDto: AddPermissionsDto = { permissionIds: ['perm1', 'perm2'] };
            const expectedResult = {
                id,
                name: 'admin',
                description: 'Admin role',
                permissions: [{ id: 'perm1', name: 'read' }, { id: 'perm2', name: 'write' }]
            };
            mockRolesService.addPermissions.mockResolvedValue(expectedResult);

            expect(await controller.addPermission(id, addPermissionsDto)).toEqual(expectedResult);
            expect(mockRolesService.addPermissions).toHaveBeenCalledWith(id, addPermissionsDto);
        });
    });
});
