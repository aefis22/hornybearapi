// auth/auth.controller.ts

import { Controller, Post, Body, Request } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('register')
    async register(@Body() body: { username: string; email: string; password: string }) {
        const { username, email, password } = body;
        return this.authService.register(username, email, password);
    }

    @Post('login')
    async login(@Body() body: { username: string; password: string }) {
        const user = await this.authService.validateUser(body.username, body.password);
        return this.authService.login(user);
    }
}
