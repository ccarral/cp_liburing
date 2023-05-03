#![feature(array_chunks)]
#![feature(iterator_try_reduce)]
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
    const ENTRIES: usize = 16;
    const IOVCNT: usize = 16;
    const IOVEC_BUFLEN: usize = 32;
    const BUFSIZE: usize = ENTRIES * IOVCNT * IOVEC_BUFLEN;
    let mut buffer = [0u8; BUFSIZE];
    let mut io_uring = IoUring::new(ENTRIES as u32)?;
    let in_file = File::open(in_path)?;
    let file_size = in_file.metadata()?.size();
    let out_file = File::create(out_path)?;

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
        .take((file_size as usize / (IOVCNT * IOVEC_BUFLEN)) + 1)
        .collect();

    let readv_es: Vec<_> = slices
        .iter_mut()
        .zip((0..BUFSIZE).step_by(IOVEC_BUFLEN * IOVCNT))
        .map(|(slice, offset)| {
            opcode::Readv::new(
                Fd(in_file.as_raw_fd()),
                slice.as_mut_ptr().cast(),
                IOVCNT as _,
            )
            .offset(offset as u64)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(0x01)
        })
        .collect();

    for e in readv_es {
        unsafe {
            io_uring.submission().push(&e)?;
        }
    }

    io_uring.submit_and_wait((file_size as usize / (IOVCNT * IOVEC_BUFLEN)) + 1)?;
    let completion_results: Vec<i32> = io_uring.completion().map(|cqe| cqe.result()).collect();
    // let write_es: Vec<_> = slices
    // .iter_mut()
    // .map(|slice| {
    // opcode::Writev::new(Fd(out_file.as_raw_fd()), slice.as_ptr().cast(), IOVCNT as _)
    // .build()
    // .flags(squeue::Flags::IO_LINK)
    // .user_data(0x02)
    // })
    // .collect();

    dbg!(&completion_results);
    // assert!(completion_results.iter().all(|read_res| *read_res > 0));
    let read_bytes: i32 = completion_results.into_iter().sum();
    dbg!(String::from_utf8(buffer[0..(read_bytes as usize)].into())?);
    Ok(())
}
