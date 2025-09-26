import { integer, pgEnum, pgTable, timestamp, varchar } from "drizzle-orm/pg-core";

export const userRole = pgEnum('user_role', ['user', 'interviewer']);

export const usersTable = pgTable("users", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  username: varchar({ length: 64 }).notNull().unique(),
  email: varchar({ length: 255 }).notNull().unique(),
  passwordHash: varchar({ length: 255 }).notNull(),
  role: userRole().notNull().default('user'),
  createdAt: timestamp({ withTimezone: false }).notNull().defaultNow(),
  updatedAt: timestamp({ withTimezone: false }).notNull().defaultNow(),
});
