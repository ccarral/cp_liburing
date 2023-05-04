#![feature(array_chunks)]
#![feature(iter_array_chunks)]
#![feature(iterator_try_reduce)]
#![feature(int_roundings)]
use anyhow::Result;
use io_uring::{opcode, squeue, types::Fd, IoUring};
use std::{
    self,
    fs::{self, File},
    io::{IoSlice, IoSliceMut, Read, Write},
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
    const ENTRIES: usize = 8;
    const IOVCNT: usize = 8;
    const IOVEC_BUFLEN: usize = 32;
    const BUFSIZE: usize = ENTRIES * IOVCNT * IOVEC_BUFLEN;
    let mut buffer = [0u8; BUFSIZE];
    let mut io_uring = IoUring::new(ENTRIES as u32)?;
    let in_file = File::open(in_path)?;
    let file_size = in_file.metadata()?.size();
    let out_file = File::create(out_path)?;

    let whole_chunks = file_size as usize / BUFSIZE;
    let partial_chunk = file_size as usize % BUFSIZE;
    let mut file_chunk_sizes = (0..whole_chunks).map(|_| BUFSIZE).collect::<Vec<_>>();
    file_chunk_sizes.push(partial_chunk);
    let offsets = file_chunk_sizes
        .into_iter()
        .enumerate()
        .map(|(i, chunk_size)| (chunk_size, i * BUFSIZE, i * BUFSIZE + chunk_size));

    for (file_chunk_sz, start, end) in offsets {
        assert!(file_chunk_sz <= BUFSIZE);
        // At most, this will always be ENTRIES
        let needed_rows = file_chunk_sz.div_ceil(IOVCNT * IOVEC_BUFLEN);
        assert!(needed_rows <= ENTRIES);
        let mut read_slices: Vec<_> = buffer
            .array_chunks_mut::<IOVEC_BUFLEN>()
            .map(AsMut::as_mut)
            .map(IoSliceMut::new)
            .collect();

        let readv_es: Vec<_> = read_slices
            .chunks_exact_mut(IOVCNT)
            .zip((start..end).step_by(IOVEC_BUFLEN * IOVCNT))
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

        assert_eq!(readv_es.len(), needed_rows);
        for e in readv_es {
            unsafe {
                io_uring.submission().push(&e)?;
            }
        }

        io_uring.submit_and_wait(needed_rows)?;
        let completion_results: Vec<i32> = io_uring.completion().map(|cqe| cqe.result()).collect();

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
            .zip((start..start + actual_bytes_read as usize).step_by(IOVEC_BUFLEN * IOVCNT))
            .map(|(slice, offset)| {
                let underlying_memory_size = slice.iter().fold(0, |acc, s| acc + s.len());
                let iovecnt = underlying_memory_size.div_ceil(IOVEC_BUFLEN);
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
            .take(needed_rows)
            .collect();

        assert_eq!(write_sqes.len(), needed_rows);
        for e in write_sqes {
            unsafe {
                io_uring.submission().push(&e)?;
            }
        }
        io_uring.submit_and_wait(needed_rows)?;
        let _: Vec<i32> = io_uring.completion().map(|cqe| cqe.result()).collect();
    }

    Ok(())
}
