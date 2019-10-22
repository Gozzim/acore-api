import { Body, Controller, Param, Patch, Post, Req, Res, UseGuards, ValidationPipe, Get, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AccountDto } from './dto/account.dto';
import { AuthGuard } from '../shared/auth.guard';
import { Account } from './account.decorator';
import { getConnection } from 'typeorm';
import { Account as AccountEntity } from './account.entity';
import { AccountPasswordDto } from './dto/account_password.dto';
import { EmailDto } from './dto/email.dto';
import { RemoteDto } from './dto/remote.dto';

@Controller('auth')
export class AuthController
{
    constructor(private readonly authService: AuthService) {}

    @Post('/signup')
    async signUp(@Body(ValidationPipe) accountDto: AccountDto, @Res() res): Promise<void>
    {
        return this.authService.signUp(accountDto, res);
    }

    @Post('/signin')
    async signIn(@Body() accountDto: AccountDto, @Res() res): Promise<void>
    {
        return this.authService.signIn(accountDto, res);
    }

    @Get('/logout')
    logout(@Res() res)
    {
        res.cookie('jwt', 'logout', { expires: new Date(Date.now() + 10), httpOnly: true });
        res.status(HttpStatus.OK).json({ status: 'success' });
    }

    @Patch('/updateMyPassword')
    @UseGuards(new AuthGuard())
    async updatePassword(@Body(ValidationPipe) accountPasswordDto: AccountPasswordDto, @Res() res, @Account('id') accountID)
    {
        return this.authService.updatePassword(accountPasswordDto, res, accountID);
    }

    @Patch('/updateMyEmail')
    @UseGuards(new AuthGuard())
    async updateEmail(@Body(ValidationPipe) emailDto: EmailDto, @Res() res, @Account('id') accountID)
    {
        return this.authService.updateEmail(emailDto, res, accountID);
    }

    @Post('/forgotPassword')
    async forgotPassword(@Body() accountDto: AccountDto, @Req() req, @Res() res): Promise<void>
    {
        return this.authService.forgotPassword(accountDto, req, res);
    }

    @Patch('/resetPassword/:token')
    async resetPassword(@Body(ValidationPipe) accountPasswordDto: AccountPasswordDto, @Res() res, @Param('token') token: string): Promise<void>
    {
        return this.authService.resetPassword(accountPasswordDto, res, token);
    }

    @Post('/rename')
    @UseGuards(new AuthGuard())
    async rename(@Body() remoteDto: RemoteDto, @Account('id') accountID)
    {
        return this.authService.rename(remoteDto, accountID);
    }

    @Post('/customize')
    @UseGuards(new AuthGuard())
    async customize(@Body() remoteDto: RemoteDto, @Account('id') accountID)
    {
        return this.authService.customize(remoteDto, accountID);
    }

    @Post('/changeFaction')
    @UseGuards(new AuthGuard())
    async changeFaction(@Body() remoteDto: RemoteDto, @Account('id') accountID)
    {
        return this.authService.changeFaction(remoteDto, accountID);
    }

    @Post('/changeRace')
    @UseGuards(new AuthGuard())
    async changeRace(@Body() remoteDto: RemoteDto, @Account('id') accountID)
    {
        return this.authService.changeRace(remoteDto, accountID);
    }

    @Get('/pulse/:days')
    async pulse(@Param('days') days: number)
    {
       return await getConnection()
          .getRepository(AccountEntity)
          .createQueryBuilder('auth')
          .select([
            'COUNT(*) AS accounts',
            'COUNT(DISTINCT(last_ip)) AS IPs'
          ])
          .where('DATEDIFF(NOW(), last_login) < ' + days)
          .getRawMany();
    }
}
