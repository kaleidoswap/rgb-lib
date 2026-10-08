# Kaleido CI runners

Build, format, lint and doctest jobs use the Linux x64 `kaleido-maker-ci`
pool. These jobs run in Ubuntu 24.04 containers and install their native
build tools inside the container, independent of the host distribution.
The host needs Docker and a GitHub runner version compatible with
`actions/checkout@v6` (v2.329.0 or newer).

Integration tests use the Linux x64 `kaleido-regtest` pool on the host.
Provision Docker with the Compose v2 plugin, Rust/rustup, a C/C++ toolchain,
CMake, pkg-config, OpenSSL development headers, and `ss` (iproute2).
The host must reach GitHub, crates.io, GitLab's container registry, GHCR,
and Docker Hub. Each runner needs its own OS account/toolchain directory
so concurrent Rust setup does not modify another runner's toolchain.

An organization admin must make both pools available to `kaleidoswap/rgb-lib`
in the runner-group repository access settings, or register repository
runners with the corresponding role labels. The repository runner API
reported zero available runners when this change was prepared. Until
access is enabled, same-repository jobs will queue. Do not assign PR jobs
to the trusted `kaleido-release` runner.

The four CI workflows include `ks/dev` in their push and PR branch filters.
Same-repository PRs and pushes use Kaleido runners; external fork PRs use
GitHub-hosted Ubuntu runners. Windows and macOS builds keep their existing
GitHub-hosted matrix coverage. Release and AI review workflows retain their
existing routing.

## Shared regtest daemon

rgb-lib binds fixed ports, including port 3002 also used by maker E2E.
`scripts/ci/regtest-lock.sh` acquires the same Docker container lock,
`regtest-host-lock`, as maker E2E before touching the stack. Acquisition
waits up to 60 minutes. The job timeout includes this wait.

Each job uses a unique `COMPOSE_PROJECT_NAME`, tears down its containers
and volumes even after test failure, and releases only its own lock.
Feature tests run after the all-features job, including after its failure.

Force cancellation or host failure can leave a lock or stack behind.
Inspect the lock's `run_id` and `rgb_lib_owner` labels and confirm its run
has stopped before removing it. The lock is never stolen automatically.
Remove the abandoned Compose project and volumes before retrying if its
fixed ports remain occupied. Do not run daemon-wide container/volume prune.
