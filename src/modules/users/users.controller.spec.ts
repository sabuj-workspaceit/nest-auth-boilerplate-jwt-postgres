import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';

import { AssignRolesToUsersDto } from './dto/assign-roles-to-users.dto';
import { User } from '../../entities/user.entity';

describe('UsersController', () => {
  let controller: UsersController;
  let service: UsersService;

  const mockUser: Partial<User> = {
    id: '1',
    firstName: 'John',
    lastName: 'Doe',
    email: 'john@example.com',
    roles: [],
  };

  const mockUsersService = {
    create: jest.fn().mockResolvedValue(mockUser),
    update: jest.fn().mockResolvedValue(mockUser),
    findAll: jest.fn(),
    findOne: jest.fn(),
    remove: jest.fn(),
    assignRoles: jest.fn(),
    assignRolesToUsers: jest.fn(),
    getRoles: jest.fn(),
    getPermissions: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    controller = module.get<UsersController>(UsersController);
    service = module.get<UsersService>(UsersService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('create', () => {
    it('should create a user', async () => {
      const createUserDto: CreateUserDto = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'password123',
        roles: ['role-id-1'],
      };

      const result = await controller.create(createUserDto);

      expect(service.create).toHaveBeenCalledWith(createUserDto);
      expect(result).toEqual(mockUser);
    });
  });

  describe('update', () => {
    it('should update a user', async () => {
      const updateUserDto: UpdateUserDto = {
        firstName: 'Jane',
        roles: ['role-id-2'],
      };

      await controller.update('1', updateUserDto);

      expect(service.update).toHaveBeenCalledWith('1', updateUserDto);
    });
  });
  describe('assignRolesToUsers', () => {
    it('should assign roles to multiple users', async () => {
      const assignRolesToUsersDto: AssignRolesToUsersDto = {
        userIds: ['user-1', 'user-2'],
        roleIds: ['role-1'],
      };

      const result = [mockUser, mockUser] as User[];
      mockUsersService.assignRolesToUsers.mockResolvedValue(result);

      const response = await controller.assignRolesToUsers(assignRolesToUsersDto);

      expect(service.assignRolesToUsers).toHaveBeenCalledWith(assignRolesToUsersDto);
      expect(response).toEqual(result);
    });
  });
});
