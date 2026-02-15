//! ptrace_playground: ptrace-based "rootless chroot" for Android/Linux.
//!
//! The heavy lifting lives in [`rootless`]. Most users only need [`Args`] and
//! [`rootless_chroot`].

pub mod rootless;

pub use rootless::{Args, rootless_chroot};
