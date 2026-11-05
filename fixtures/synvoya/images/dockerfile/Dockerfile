# syntax=docker/dockerfile:1
ARG NODE=20.11.1
ARG PHP_TAG=8.3-apache
ARG BASE_IMAGE
FROM --platform=$BUILDPLATFORM node:${NODE}-slim AS build
FROM build AS test
FROM scratch
FROM docker.io/library/php:${PHP_TAG}
FROM ${BASE_IMAGE}
FROM mcr.microsoft.com/dotnet/aspnet:8.0.4-bookworm-slim
FROM bitnami/python:3.12
FROM jenkins/jenkins:2.426.1-lts-jdk17
FROM postgres:12
FROM unknown/thing:1.0
