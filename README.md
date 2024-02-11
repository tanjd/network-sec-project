# Network security (sockets)

[![DevContainer Enabled](https://img.shields.io/badge/DevContainer-Enabled-blue?logo=docker)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/tanjd/network-sec-project)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

## Project Description

This project is an evolution of a previous module project focused on Network Security. The original task involved simulating the transmission of IP packets with various nodes and router, with nodes representing clients and a router acting as the server.

For this V2 iteration, the primary objective is code refinement and enhancement, leveraging insights gained from professional software engineering experience accumulated over the past 1-2 years. The overarching goal is to implement industry best practices, including improved developer experience (DevContainer, linters, pre-commit hooks, Poetry for Python, and CI), Test-Driven Development (TDD), and adherence to SOLID principles.

At its current stage, the project features the establishment of a server and client. The client sends a message to the server, which then echoes the message back to the client.

## Getting Started

### Develop with devcontainer (VSCode Only)

1. Start your Docker.
2. Install the [Dev Container extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) on VSCode if not installed.
3. Select `Reopen in Container` from the VSCode command palette.
4. Run `make` to access make commands

This set-up ensures that you have the necessary tools for development within this repository.

## TODO

1. Simulate Packet Structure
2. Client to Client message
3. Add some CI pipeline
