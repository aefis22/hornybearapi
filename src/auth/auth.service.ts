import { Injectable, UnauthorizedException } from '@nestjs/common';
import {JwtService} from "@nestjs/jwt";
import {PrismaService} from "../../prisma/prisma.service";
import {User} from "@prisma/client";
import * as bcrypt from 'bcryptjs';
@Injectable()
export class AuthService {
    constructor(
       private readonly jwtService: JwtService,
       private readonly prisma: PrismaService
    ) {}

    async validateUser(username: string, password: string): Promise<User | null> {
        const user = await this.prisma.user.findUnique({ where: { username } });
        if (user && (await bcrypt.compare(password, user.password))) {
            return user;
        }
        throw new UnauthorizedException('Invalid credentials');
    }

    async login(user: User) {
        const payload = { username: user.username, sub: user.id};
        return {
            access_token: this.jwtService.sign(payload),
        };
    }
    async register(username: string, email: string, password: string) {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await this.prisma.user.create({
            data: { username, email, password: hashedPassword },
        });
        return this.login(newUser);
    }
}
