import crypto from 'crypto';
import { db } from '@/db/client';
import { usersTable } from '@/db/schema';
import { or, eq } from 'drizzle-orm';

export type VerifiedUser = {
  id: string | number;
  email: string;
  username: string;
  role: 'interviewer' | 'user';
};

export async function verifyUserCredentials(identifier: string, password: string): Promise<VerifiedUser | null> {
  const rows = await db
    .select({ id: usersTable.id, email: usersTable.email, username: usersTable.username, passwordHash: usersTable.passwordHash, role: usersTable.role })
    .from(usersTable)
    .where(or(eq(usersTable.email, identifier), eq(usersTable.username, identifier)))
    .limit(1);
  const row = rows[0];
  if (!row) return null;
  if (!verifyPassword(password, row.passwordHash)) return null;
  return { id: row.id, email: row.email, username: row.username, role: row.role as 'user' | 'interviewer' };
}

export function hashPassword(plain: string): string {
  const salt = process.env.PASSWORD_SALT ?? 'development-only-salt';
  return crypto.createHmac('sha256', salt).update(plain).digest('hex');
}

export function verifyPassword(plain: string, hashed: string): boolean {
  return hashPassword(plain) === hashed;
}


