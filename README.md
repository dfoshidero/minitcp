# minitcp

A userspace Ethernet/TCP stack. Development happens inside a Dev Container so the environment has a TUN device and the capabilities needed to work with raw network interfaces.

## Start the Dev Container

You need Docker running on the host (Docker Engine on Linux or WSL2 is preferred). Then open this repo in [Cursor](https://cursor.com) or [VS Code](https://code.visualstudio.com) with the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension installed.

1. Clone this repository and open the folder.
2. When prompted, choose **Reopen in Container**.
   If no prompt appears, open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run **Dev Containers: Reopen in Container**.

The container builds from [`.devcontainer/Dockerfile`](.devcontainer/Dockerfile), installs the Rust toolchain, and starts with:

- `NET_ADMIN` and `NET_RAW` capabilities
- `/dev/net/tun` attached

Once the container is running, you can build and run the project as usual:

```bash
cargo run
```

### Dev Container CLI

If you prefer not to use the editor:

```bash
npm install -g @devcontainers/cli
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

## Docker Desktop

We're intentionally not using Docker Desktop's `--network=host`. Docker documents that Desktop host networking operates at Layer 4 rather than exposing lower-level protocols such as Ethernet, which isn't useful for our Ethernet-stack project.
