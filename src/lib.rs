/*

Copyright (c) 2020 Pawel Kraszewski. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of
       conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of
       conditions and the following disclaimer in the documentation and/or other materials
       provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

//! Adapter of Linux' `signalfd` to be used with [`mio`] 0.7
//! ```
//! use std::{thread, time::Duration};
//! use std::error::Error;
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicBool, Ordering};
//!
//! use mio::{Events, Interest, Poll, Token};
//! use pakr_signals::{Pid, Sig, SigSet};
//!
//! use pakr_mio_signalfd::*;
//!
//! const TOK: Token = Token(0);
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     const SIGS: &[Sig] = &[Sig::USR2, Sig::USR1, Sig::QUIT];
//!
//!     // SigSet we are working with
//!     let sigs = SigSet::from(SIGS);
//!
//!     // Make completion flags to be shared between threads
//!     let done = Arc::new(AtomicBool::new(false));
//!     let cdone = done.clone();
//!
//!     // Disable default hadlers of signals we play with
//!     sigs.disable_default_handler()?;
//!
//!     // Spawn background thread that will (slowny) bomb our process with signals
//!     let bomber = thread::spawn(move || {
//!         // Get my own PID
//!         let my_pid = Pid::own().unwrap();
//!
//!         // Repeat some times
//!         for _ in 0..2 {
//!             // For each signal on the list
//!             for &sig in SIGS {
//!                 // Sleep a second
//!                 thread::sleep(Duration::from_secs(1));
//!
//!                 println!("Sending {:?}", sig);
//!
//!                 //  ... then self-send signal
//!                 sig.send_to(my_pid).unwrap();
//!             }
//!         }
//!         // Tell we're done
//!         cdone.store(true, Ordering::Relaxed)
//!     });
//!
//!     // Create a poll instance.
//!     let mut poll = Poll::new()?;
//!
//!     // Create storage for events.
//!     let mut events = Events::with_capacity(128);
//!
//!     // Create instance of signal watcher
//!     let mut watcher = SignalFd::new(&sigs)?;
//!
//!     // Register watcher in mio registry. This handle is readable only
//!     poll.registry().register(
//!         &mut watcher,
//!         TOK,
//!         Interest::READABLE,
//!     )?;
//!
//!     // Repeat while not told done
//!     while !done.load(Ordering::Relaxed) {
//!
//!         // Poll Mio for events, blocking until we get an event or timeout on 3s.
//!         poll.poll(&mut events, Some(Duration::from_secs(3)))?;
//!
//!         // Process each event.
//!         for event in events.iter() {
//!             // We can use the token we previously provided to `register` to
//!             // determine for which socket the event is.
//!             match event.token() {
//!                 TOK => {
//!                     println!("Handled event");
//!                     while let Some(siginfo) = watcher.read()? {
//!                         println!("Got signal {:?}", Sig::from(siginfo.ssi_signo as i32));
//!                     }
//!                     println!("---");
//!                 }
//!
//!                 // We don't expect any events with tokens other than those we provided.
//!                 _ => { println!("Other event"); }
//!             }
//!         }
//!     }
//!
//!     // Join with bomber thread
//!     bomber.join().unwrap();
//!
//!     // Re-enable default handlers
//!     sigs.enable_default_handler()?;
//!
//!     // We're done
//!     Ok(())
//! }
//! ```

use std::{
    io, mem,
    mem::MaybeUninit,
    os::unix::io::{AsRawFd, RawFd},
};

use libc::c_void;
/// Re-exported [`libc::signalfd_siginfo`].
pub use libc::signalfd_siginfo as SigInfo;
use mio::{event::Source, Interest, Registry, Token, unix::SourceFd};
use pakr_signals::SigSet;

#[cfg(not(target_os = "linux"))]
compile_error!("signalfd is a linux specific feature");

/// [`SignalFd`] can be used to create mio-compatible signal handlers.
pub struct SignalFd { fd: i32 }

impl SignalFd {
    /// Create a new signalfd watching the given signal set.
    pub fn new(sigset: &SigSet) -> io::Result<Self> {
        let flags = libc::TFD_NONBLOCK | libc::TFD_CLOEXEC;

        let fd = unsafe { libc::signalfd(-1, sigset.as_ptr(), flags) };
        if fd == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { fd })
        }
    }

    /// Acknowledges received signal.
    /// **It must be called** after catching signal to acknowlege that signal. If you don't
    /// [read](`SignalFd::read`), the same signal is re-issued on the next poll iteration.
    ///
    /// Returns:
    ///  - `Ok(None)` - if there was no signal waiting ([`SignalFd`] is opened
    ///     as [NONBLOCK](`libc::TFD_NONBLOCK`))
    ///  - `Ok(Some(SigInfo))` - if there was pending signal information
    ///  - `Err(...)` - if there was error reading signal information
    ///
    pub fn read(&self) -> io::Result<Option<SigInfo>> {
        const SI_SIZE: isize = mem::size_of::<SigInfo>() as isize;

        let mut si_mem = MaybeUninit::<SigInfo>::uninit();

        let ret = unsafe {
            libc::read(
                self.fd,
                si_mem.as_mut_ptr() as *mut c_void,
                SI_SIZE as usize,
            )
        };

        match ret {
            SI_SIZE => {
                let si = unsafe { si_mem.assume_init() };
                Ok(Some(si))
            }

            -1 => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN {
                    Ok(None)
                } else {
                    Err(io::Error::from_raw_os_error(errno))
                }
            }

            other => panic!("reading a timerfd should never yield {} bytes", other),
        }
    }
}

impl AsRawFd for SignalFd {
    fn as_raw_fd(&self) -> RawFd { self.fd }
}

impl Source for SignalFd {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.fd).register(registry, token, interest)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interest: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.fd).reregister(registry, token, interest)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        SourceFd(&self.fd).deregister(registry)
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) { let _ = unsafe { libc::close(self.fd) }; }
}
