import { NestFactory } from '@nestjs/core';
import { AppModule } from '../src/app.module';
import { DataSource } from 'typeorm';

async function bootstrap() {
    const app = await NestFactory.createApplicationContext(AppModule);
    const dataSource = app.get(DataSource);

    console.log('🗑️  Dropping and syncing database schema...');
    await dataSource.synchronize(true);
    console.log('✅ Database schema reset successfully!');

    await app.close();
}

bootstrap();
