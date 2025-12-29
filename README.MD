# apple crate collection

At some point I started a sideloader rewrite in Rust in
parallel of my D rewrite, but now that there are a few 
alternatives, I am not sure of whether I will finish it.

Anyway, for that I wrote a few shiny crates that could help
rewrite iTunes or anything apple related.

Here is a breakdown of every crate here:

### adi

Abstracts an ADI connection, allows direct communication with ADI code.

### adid-proxy

Create an `adi::ADIProxy` on a Darwin system that can connect to the `adid` daemon.

### android-coreadi

Create an `adi::ADIProxy` on any Unix system (TODO: add Windows support) from
any `libCoreADI.so` distribution supporting your architecture.

### apple-account (unfinished yet)

A fully-featured, type-safe, well-designed Apple server API wrapper.

You can log into an Apple account via GSA APIs with any ADIProxy, fetch the tokens,
while handling every error correctly, including Apple's server errors.

(currently, the Grandslam part lacks the code to do 2FA without a browser,
and the iTunes connection part is not yet implemented

### apple-codesign(-quick) (unfinished yet)

A port of Sideloader's barebone very fast signer in Rust.

Sideloader's signer is less hacky than zsign and is way faster than apple-codesign-rs 
(probably partly because it takes a few shortcuts too in addition of being multithreaded
and designed with performance in mind).

### elf-loader

A better minimal cross-platform elf-loader crate.

I will add feature as needed for the other packages

### fairplay (unfinished yet)

Abstracting CoreFP for use on any system, a bit like `adi`, will be used in 
`apple-account` iTunes part.

### plist-macros

Allows declarative declaration of plist.

### purple-builder (unfinished yet)

A reimplementation of Xcode maybe some day? (but Rust GUI situation is not great, so I postponed that D:)

### super-sideloader

That Sideloader rewrite in Rust I postponed. Currently, it's full of apple-account's testing code.

### there should be a separate xcode api crate

but I did not start to work on it :p

## Okay but why have you rewrote everything?

I wasn't satisfied with what was already available :p.

## Addendum

Don't hesitate to reach me out if you have any questions, in the discussion tab here or on Discord!
I do my best to be reactive and useful.

Also, if you enjoy my work, please consider giving me a small tip <3
