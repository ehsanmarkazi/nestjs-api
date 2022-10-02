import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from './../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { JwtService } from "@nestjs/jwt"
import { ConfigService } from '@nestjs/config';




@Injectable({})
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService
    ) { }

    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password);

        const ckUser = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if (ckUser) throw new ForbiddenException('Credentials incorrect')

        const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash,
            },

        });
        delete user.hash;

        return this.signToken(user.id, user.email);

    }


    async signin(dto: AuthDto) {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            },
        });

        if (!user) throw new ForbiddenException('Credentials incorrect');

        const pwMatches = await argon.verify(user.hash, dto.password);
        if (!pwMatches) throw new ForbiddenException('Credentials incorrect')

        return this.signToken(user.id, user.email);
    }


    async signToken(
        userId: string,
        email: string
    ): Promise<{access_token:string}> {
        const payload = {
            sub: userId,
            email
        }
        const secret = this.config.get('JWT_SECRET');

        const token = await this.jwt.signAsync(
            payload,{
            expiresIn:'30m',
            secret:secret
        });

        return{
            access_token: token,
        };
 
    }

}


