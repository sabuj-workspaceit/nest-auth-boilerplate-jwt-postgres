import { Test, TestingModule } from '@nestjs/testing';
import { UsersService } from './users.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { User } from '../../entities/user.entity';
import { Role } from '../../entities/role.entity';
import { Repository } from 'typeorm';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { hashPassword } from '../../utils/hash.util';
import { UpdateUserDto } from './dto/update-user.dto';

// Mock hash utility
jest.mock('../../utils/hash.util', () => ({
  hashPassword: jest.fn().mockResolvedValue('hashedPassword'),
}));

describe('UsersService', () => {
  let service: UsersService;
  let usersRepository: Repository<User>;
  let rolesRepository: Repository<Role>;

  const mockUser = {
      id: 'user-id',
      email: 'old@example.com',
      password: 'oldPassword',
      firstName: 'Old',
      lastName: 'Name',
      roles: [],
      isEmailVerified: true,
  } as unknown as User;

  const mockUsersRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
  };

  const mockRolesRepository = {
    findBy: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUsersRepository,
        },
        {
          provide: getRepositoryToken(Role),
          useValue: mockRolesRepository,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    usersRepository = module.get<Repository<User>>(getRepositoryToken(User));
    rolesRepository = module.get<Repository<Role>>(getRepositoryToken(Role));

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('update', () => {
    it('should update user email and reset verification', async () => {
      const updateUserDto: UpdateUserDto = {
        email: 'new@example.com',
      };

      mockUsersRepository.findOne.mockResolvedValueOnce(mockUser); // findOne(id)
      mockUsersRepository.findOne.mockResolvedValueOnce(null); // findOne({ where: { email } })
      mockUsersRepository.save.mockImplementation((user) => Promise.resolve(user));

      const result = await service.update('user-id', updateUserDto);

      expect(mockUsersRepository.findOne).toHaveBeenCalledWith({ where: { email: 'new@example.com' } });
      expect(result.email).toBe('new@example.com');
      expect(result.isEmailVerified).toBe(false);
    });

    it('should throw ConflictException if new email already exists', async () => {
      const updateUserDto: UpdateUserDto = {
        email: 'existing@example.com',
      };

      mockUsersRepository.findOne.mockResolvedValueOnce(mockUser); // findOne(id)
      mockUsersRepository.findOne.mockResolvedValueOnce({ id: 'other-id' } as User); // findOne({ where: { email } })

      await expect(service.update('user-id', updateUserDto)).rejects.toThrow(ConflictException);
    });

    it('should hash password if provided', async () => {
      const updateUserDto: UpdateUserDto = {
        password: 'newPassword',
      };

      mockUsersRepository.findOne.mockResolvedValueOnce(mockUser);
      mockUsersRepository.save.mockImplementation((user) => Promise.resolve(user));

      const result = await service.update('user-id', updateUserDto);

      expect(hashPassword).toHaveBeenCalledWith('newPassword');
      expect(result.password).toBe('hashedPassword');
    });

    it('should update other fields correctly', async () => {
      const updateUserDto: UpdateUserDto = {
        firstName: 'New',
        lastName: 'Name',
      };

      mockUsersRepository.findOne.mockResolvedValueOnce(mockUser);
      mockUsersRepository.save.mockImplementation((user) => Promise.resolve(user));

      const result = await service.update('user-id', updateUserDto);

      expect(result.firstName).toBe('New');
      expect(result.lastName).toBe('Name');
    });
  });
});
