# Horcrust
Horcrust is a command-line-tool which splits a file into encrypted shards for safekeeping. As long as the specified threshold is met, a user can resurrect their original file at any time - no password necessary.

This project is a Rust implementation of the original [horcrux](https://github.com/jesseduffield/horcrux) 


## Usage
Horcrust only has 2 commands `split` and `bind`.

**Splitting**

```sh
horcrust split classified.txt --shards 4 --threshold 2
```

The split command supports standard input!

```sh
cat ../files/classified.txt | horcrust split --shards 4 --threshold 2
```

You can specify where the shards can be placed using the optional `directory` argument 

```sh
horcrust split classified.txt --shards 4 --threshold 4 --destination ../../documents/stash
```

**Binding**
When you're ready to recover your secret do the following.
```sh
horcrust bind ../secrets
```


## Installation 

**Homebrew**

```sh
brew tap codycline/taps
brew install codycline/taps/horcrust
```

**Chocolatey**

[![chocolatey](https://img.shields.io/chocolatey/v/horcrust)](https://community.chocolatey.org/packages/horcrust)

```ps
choco install horcrust
```

**Crates**

[![crates.io](https://img.shields.io/crates/v/horcrust)](https://crates.io/crates/horcrust)

```
cargo install horcrust
```

**Install directly**

1. [Download latest release](https://github.com/CodyCline/horcrux-rs/releases/latest) for your system.

2. Unpack the compressed archive into your bin folder

```sh
sudo tar -xf ./Downloads/horcrust-VERSION-x86_64-unknown-linux-musl.tar.gz
 horcrust --directory ~/usr/local/bin
```


### Testing 

```
cargo clippy
cargo test -- --test-threads=1
```