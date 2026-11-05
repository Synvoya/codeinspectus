import { Module, ValidationPipe } from "@nestjs/common";
import { APP_PIPE } from "@nestjs/core";
@Module({
  providers: [{ provide: APP_PIPE, useValue: new ValidationPipe() }],
})
export class AppModule {}
