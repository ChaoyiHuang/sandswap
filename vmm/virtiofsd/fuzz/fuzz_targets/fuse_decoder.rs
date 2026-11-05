#![no_main]

//! Fuzz the real virtiofsd FUSE entry: arbitrary bytes are written into guest
//! memory as one FUSE request, wrapped in a mock split-virtqueue chain, and
//! passed to `Server::handle_message` over a real `PassthroughFs` rooted at a
//! temporary directory. This exercises the in-header decode, the opcode
//! dispatch and the per-op payload decoding — the guest→virtiofsd boundary.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::os::raw::c_int as RawFd;

use libfuzzer_sys::fuzz_target;
use rate_limiter::{BucketReduction, TokenType};
use virtio_queue::mock::MockSplitQueue;
use virtio_queue::Descriptor;
use virtiofsd::descriptor_utils::{Reader, Writer};
use virtiofsd::fs_cache_req_handler::FsCacheReqHandler;
use virtiofsd::passthrough::{Config as PtConfig, PassthroughFs};
use virtiofsd::server::Server;
use vm_memory::bitmap::AtomicBitmap;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

const REQ_ADDR: u64 = 0x1000;
const RESP_ADDR: u64 = 0x8000;
const RESP_LEN: u32 = 4096;
const MAX_REQ: usize = 0x6000;

struct NoDax;
impl FsCacheReqHandler for NoDax {
    fn map(&mut self, _: u64, _: u64, _: u64, _: u64, _: RawFd) -> io::Result<()> {
        Ok(())
    }
    fn unmap(&mut self, _: Vec<virtiofsd::fuse::RemovemappingOne>) -> io::Result<()> {
        Ok(())
    }
}

struct Harness {
    mem: GuestMemoryMmap<AtomicBitmap>,
    server: Server<PassthroughFs>,
}

thread_local! {
    static HARNESS: RefCell<Option<Harness>> = RefCell::new(None);
}

fn with_harness<F: FnOnce(&Harness)>(f: F) {
    HARNESS.with(|slot| {
        if slot.borrow().is_none() {
            let root = std::env::temp_dir().join(format!(
                "sandswap-fuse-fuzz-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("allow")).expect("create allow dir");
            fs::write(root.join("allow/file"), b"seed").expect("seed file");
            let fs_h = PassthroughFs::new(PtConfig {
                root_dir: root.to_string_lossy().into_owned(),
                ..Default::default()
            })
            .expect("PassthroughFs::new");
            fs_h.open_root_node().expect("open_root_node");
            // FilterList opens whitelist entries as HOST paths (absolute);
            // the exported key is the basename.
            let allow = root.join("allow");
            let server = Server::new(fs_h, &[allow.to_string_lossy().into_owned()], Some("fuzz-alias"))
                .expect("Server::new");
            let mem = GuestMemoryMmap::<AtomicBitmap>::from_ranges(&[(GuestAddress(0), 0x1_0000)])
                .expect("guest memory");
            *slot.borrow_mut() = Some(Harness { mem, server });
        }
        let borrowed = slot.borrow();
        f(borrowed.as_ref().expect("harness initialized"));
    });
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_REQ {
        return;
    }
    with_harness(|h| {
        h.mem
            .write_slice(data, GuestAddress(REQ_ADDR))
            .expect("write request");
        let zeros = vec![0u8; RESP_LEN as usize];
        h.mem
            .write_slice(&zeros, GuestAddress(RESP_ADDR))
            .expect("clear response");

        let queue = MockSplitQueue::new(&h.mem, 16);
        let chain = queue
            .build_desc_chain(&[
                Descriptor::new(REQ_ADDR, data.len() as u32, 1, 1),
                Descriptor::new(RESP_ADDR, RESP_LEN, 2, 0),
            ])
            .expect("build descriptor chain");
        let reader = Reader::new(&h.mem, chain.clone()).expect("Reader::new");
        let writer = Writer::new(&h.mem, chain).expect("Writer::new");

        let mut reduction = BucketReduction::Success;
        let mut token = TokenType::Ops;
        let _ = h.server.handle_message(
            reader,
            writer,
            None::<&mut NoDax>,
            &mut None,
            &mut reduction,
            &mut token,
        );
    });
});
