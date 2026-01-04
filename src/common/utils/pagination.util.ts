import { Repository, SelectQueryBuilder, ObjectLiteral } from 'typeorm';
import { PaginationDto, SortOrder } from '../dto/pagination.dto';
import { PaginatedResult } from '../interfaces/paginated-result.interface';

export async function paginate<T extends ObjectLiteral>(
    repository: Repository<T> | SelectQueryBuilder<T>,
    paginationDto: PaginationDto,
    searchFields: string[] = [],
): Promise<PaginatedResult<T>> {
    const page = Number(paginationDto.page) || 1;
    const limit = Number(paginationDto.limit) || 10;
    const skip = (page - 1) * limit;
    const sortBy = paginationDto.sortBy || 'createdAt';
    const sortOrder = paginationDto.sortOrder || SortOrder.DESC;

    let queryBuilder: SelectQueryBuilder<T>;

    if (repository instanceof Repository) {
        queryBuilder = repository.createQueryBuilder('entity');
    } else {
        queryBuilder = repository;
    }

    // Search
    if (paginationDto.search && searchFields.length > 0) {
        queryBuilder.andWhere(
            `(${searchFields
                .map((field) => `${field} ILIKE :search`)
                .join(' OR ')})`,
            { search: `%${paginationDto.search}%` },
        );
    }

    // Sort
    // Check if sortBy contains a dot (indicating a relation)
    if (sortBy.includes('.')) {
        queryBuilder.orderBy(sortBy, sortOrder);
    } else {
        // Assume it's a field on the main entity
        const alias = queryBuilder.alias;
        queryBuilder.orderBy(`${alias}.${sortBy}`, sortOrder);
    }

    // Pagination
    queryBuilder.skip(skip).take(limit);

    const [results, totalResults] = await queryBuilder.getManyAndCount();

    const totalPages = Math.ceil(totalResults / limit);

    return {
        results,
        page,
        limit,
        totalPages,
        totalResults,
    };
}
