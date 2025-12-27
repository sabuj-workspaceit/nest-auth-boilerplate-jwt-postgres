import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    ManyToOne,
    JoinColumn,
} from 'typeorm';
import { User } from '../../../entities/user.entity';

@Entity('password_resets')
export class PasswordReset {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ name: 'user_id' })
    userId: string;

    @ManyToOne(() => User, (user) => user.passwordResets, {
        onDelete: 'CASCADE',
    })
    @JoinColumn({ name: 'user_id' })
    user: User;

    @Column({ nullable: true })
    token: string;

    @Column({ nullable: true })
    otp: string;

    @Column({ name: 'expires_at' })
    expiresAt: Date;

    @Column({ name: 'is_used', default: false })
    isUsed: boolean;

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;
}
