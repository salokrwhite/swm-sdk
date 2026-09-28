#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(not(windows))]
mod other;
#[cfg(not(windows))]
pub(crate) use other::*;

pub(crate) fn supported() -> bool {
    cfg!(windows) && (cfg!(target_arch = "x86_64") || cfg!(target_arch = "x86"))
}
