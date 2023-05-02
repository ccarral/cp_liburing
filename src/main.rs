#![feature(array_chunks)]
use anyhow::Result;
use io_uring::{opcode, squeue, types::Fd, IoUring};
use std::{
    self,
    ffi::CString,
    fs::{self, File},
    io::{Error, IoSlice, IoSliceMut, Read, Write},
    os::{fd::AsRawFd, unix::prelude::MetadataExt},
    path::PathBuf,
};

mod cmd;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (in_path, out_path) = cmd::parse_args(&args).expect("args error");
    // naive_cp(&in_path, &out_path).expect("naive cp");
    liburing_cp(&in_path, &out_path).expect("uring cp");
    let original_contents = fs::read_to_string(&in_path).expect("reading original file");
    let actual_contents = fs::read_to_string(&out_path).expect("reading output file");
    assert_eq!(original_contents, actual_contents);
}

fn naive_cp(in_path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    let mut in_file = File::open(in_path)?;
    let mut out_file = File::create(out_path)?;
    const BUFSIZE: usize = 1024;
    let mut buffer = [0u8; BUFSIZE];
    loop {
        let bytes_read = in_file.read(&mut buffer)?;
        if bytes_read == 0 {
            return Ok(());
        }
        out_file.write_all(&buffer[0..bytes_read])?;
    }
}

fn liburing_cp(in_path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    // NOTE: Changed the number of entries to 1
    const ENTRIES: usize = 8;
    const IOVCNT: usize = 8;
    const IOVEC_BUFLEN: usize = 8;
    const BUFSIZE: usize = ENTRIES * IOVCNT * IOVEC_BUFLEN;
    let mut buffer = [0u8; BUFSIZE];
    let mut io_uring = IoUring::new(ENTRIES as u32)?;
    let in_file = File::open(in_path)?;

    let mut slices: Vec<_> = buffer
        .array_chunks_mut::<{ IOVCNT * IOVEC_BUFLEN }>()
        .map(|slice| {
            let mut read_chunks: Vec<IoSliceMut> = slice
                .chunks_exact_mut(IOVEC_BUFLEN)
                .map(IoSliceMut::new)
                .collect();

            assert_eq!(IOVCNT, read_chunks.len());
            read_chunks
        })
        .collect();

    let readv_es: Vec<_> = slices
        .iter_mut()
        .map(|slice| {
            opcode::Readv::new(
                Fd(in_file.as_raw_fd()),
                slice.as_mut_ptr().cast(),
                IOVCNT as _,
            )
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(0x01)
        })
        .collect();

    assert_eq!(readv_es.len(), ENTRIES);

    for e in readv_es {
        unsafe {
            io_uring.submission().push(&e)?;
        }
    }

    io_uring.submit_and_wait(ENTRIES)?;
    let completion_results: Vec<i32> = io_uring.completion().map(|cqe| cqe.result()).collect();

    dbg!(&completion_results);
    assert!(completion_results.iter().all(|read_res| *read_res > 0));
    dbg!(String::from_utf8(buffer.into())?);
    Ok(())
}
