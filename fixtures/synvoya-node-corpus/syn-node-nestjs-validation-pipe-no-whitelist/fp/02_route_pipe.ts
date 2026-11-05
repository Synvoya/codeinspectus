import { Body, Controller, Post, ValidationPipe } from "@nestjs/common";
@Controller("x")
export class XController {
  @Post()
  create(@Body(new ValidationPipe()) body: unknown) {
    return body;
  }
}
