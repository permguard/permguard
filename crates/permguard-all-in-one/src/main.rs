#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

include!("main_entry.rs");

// jemalloc on Linux, whose background threads return idle memory to the system after a burst
// (BUG-0056): the system allocator keeps the arenas a burst grew. Its options are embedded at
// build time, `JEMALLOC_SYS_WITH_MALLOC_CONF` in `.cargo/config.toml`.
#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
