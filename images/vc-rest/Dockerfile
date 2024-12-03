#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG GO_ALPINE_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${GO_ALPINE_VER} AS golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . src/github.com/dellekappa/vcs
WORKDIR src/github.com/dellekappa/vcs
ENV EXECUTABLES go git

FROM golang AS vcs
ARG GO_PROXY
RUN GOPROXY=${GO_PROXY} make vc-rest


FROM alpine:${ALPINE_VER} AS base
LABEL org.opencontainers.image.source https://github.com/dellekappa/vcs
COPY --from=vcs /go/src/github.com/dellekappa/vcs/.build/bin/vc-rest /usr/local/bin

ENTRYPOINT ["vc-rest"]