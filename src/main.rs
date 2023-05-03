#![feature(array_chunks)]
#![feature(iterator_try_reduce)]
#![feature(int_roundings)]
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
    const ENTRIES: usize = 32;
    const IOVCNT: usize = 16;
    const IOVEC_BUFLEN: usize = 32;
    const BUFSIZE: usize = ENTRIES * IOVCNT * IOVEC_BUFLEN;
    let mut buffer = [0u8; BUFSIZE];
    let mut io_uring = IoUring::new(ENTRIES as u32)?;
    let in_file = File::open(in_path)?;
    let file_size = in_file.metadata()?.size();
    let out_file = File::create(out_path)?;

    let needed_rows = (file_size as usize).div_ceil(IOVCNT * IOVEC_BUFLEN);
    let mut read_slices: Vec<_> = buffer
        .array_chunks_mut::<IOVEC_BUFLEN>()
        .map(AsMut::as_mut)
        .map(IoSliceMut::new)
        .collect();

    assert_eq!(read_slices.len(), IOVCNT * ENTRIES);
    assert!(needed_rows <= ENTRIES);

    let readv_es: Vec<_> = read_slices
        .chunks_exact_mut(IOVCNT)
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
        .take(needed_rows)
        .collect();

    assert_eq!(needed_rows, readv_es.len());
    for e in readv_es {
        unsafe {
            io_uring.submission().push(&e)?;
        }
    }

    dbg!(BUFSIZE);
    dbg!(file_size);
    dbg!(needed_rows);

    io_uring.submit_and_wait(needed_rows)?;
    let completion_results: Vec<i32> = io_uring.completion().map(|cqe| cqe.result()).collect();
    let read_bytes: i32 = completion_results.iter().sum();
    let original_contents = fs::read_to_string(in_path)?;
    let read_contents = String::from_utf8(buffer[0..(read_bytes as usize)].into())?;
    assert_eq!(original_contents, read_contents);

    dbg!(&completion_results);
    let actual_bytes_read: i32 = completion_results.iter().sum();

    let bytes_read_buffer = &buffer[..actual_bytes_read as usize];
    let write_buf_chunks = bytes_read_buffer.array_chunks::<IOVEC_BUFLEN>();
    let rem = write_buf_chunks.remainder();

    let write_slices: Vec<_> = write_buf_chunks
        .map(AsRef::as_ref)
        .chain(std::iter::once(rem))
        .map(IoSlice::new)
        .collect();

    let write_sqes: Vec<_> = write_slices
        .chunks(IOVCNT)
        .zip((0..actual_bytes_read).step_by(IOVEC_BUFLEN * IOVCNT))
        .map(|(slice, offset)| {
            let underlying_memory_size = slice.iter().fold(0, |acc, s| acc + s.len());
            let iovecnt = underlying_memory_size.div_ceil(IOVEC_BUFLEN);
            dbg!(iovecnt);
            opcode::Writev::new(
                Fd(out_file.as_raw_fd()),
                slice.as_ptr().cast(),
                iovecnt as _,
            )
            .offset(offset as u64)
            .build()
            .flags(squeue::Flags::IO_LINK)
            .user_data(0x02)
        })
        .collect();

    let write_len = write_sqes.len();
    assert_eq!(write_len, needed_rows);
    for e in write_sqes {
        unsafe {
            io_uring.submission().push(&e)?;
        }
    }
    io_uring.submit_and_wait(needed_rows)?;
    Ok(())
}
