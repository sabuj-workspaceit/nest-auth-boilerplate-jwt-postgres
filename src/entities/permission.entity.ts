import {
    Entity,
    PrimaryGeneratedColumn,
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    ManyToOne,
    OneToMany,
    JoinColumn,
} from 'typeorm';

@Entity('permissions')
export class Permission {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ unique: true })
    slug: string;

    @Column({ nullable: true })
    description: string;

    @ManyToOne(() => Permission, (permission) => permission.children, {
        nullable: true,
        onDelete: 'CASCADE',
    })
    @JoinColumn({ name: 'parent_id' })
    parent: Permission;

    @OneToMany(() => Permission, (permission) => permission.parent)
    children: Permission[];

    @CreateDateColumn({ name: 'created_at' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at' })
    updatedAt: Date;
}
