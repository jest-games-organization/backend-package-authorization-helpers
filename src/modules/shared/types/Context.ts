import { ExpressContext } from './ExpressContext';

export type Context<T extends { [key: string]: unknown }> = ExpressContext & { data: T | null };
