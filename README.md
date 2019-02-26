# WALLET PROTOTYPE

# Pre-Requisite 

Make sure to download, build and have the [cardano-http-bridge]() running on port 1337.

```
$ git clone git@github.com:input-output-hk/cardano-http-bridge.git
$ cargo run --release --port 1337
```

> NOTE:  
> `cargo` is the Rust package manager / build assistant (~ `stack` in Haskell). 


Give it a bit of time (~30 minutes to an hour) to sync with mainnet, downloading blocks 
and epochs from peers (this should create a `.hermes` folder on your `$HOME` that contains 
a bunch of serialized files).

# How to Run

This is just plain stack

```
$ stack build --fast --exec "stack exec -- cardano-minimal-viable-wallet-exe"
```
